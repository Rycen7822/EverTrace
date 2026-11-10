//! Original Native JSONRPC transport, not a command/execution API or a qualified namespace.
use std::{
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};

use evertrace_domain::evidence::{
    CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
    CorrelationField, CorrelationFieldClaim, EvidenceByteRange, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceObservation, SourceReceipt,
    SourceRevisionMode, SourceRole,
};
use rustix::event::{PollFd, PollFlags, poll};
use serde::{Deserialize, Deserializer, de::IgnoredAny};
use tungstenite::{
    Error as WireError, Message, client::client_with_config, protocol::WebSocketConfig,
};

use crate::{CaptureRecordBody, CaptureRecordInput, CaptureRuntime, RuntimeSnapshot, goal_source};

pub const SOURCE_REVISION: &str = "native-user-shell-live-0.166.0-v1";
pub const ADAPTER_VERSION: &str = "native-user-shell-live-0.166.0-v1:capture-5";
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

pub(crate) fn id_present<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<bool, D::Error> {
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

fn uuid(text: &str) -> Option<&str> {
    uuid::Uuid::parse_str(text)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == text)?;
    Some(text)
}

impl Event {
    fn decode(raw: &str) -> Option<Self> {
        let event: Self = serde_json::from_str(raw).ok()?;
        let item = &event.params.item;
        if event.id
            || !matches!(
                (event.method.as_str(), item.status.as_str()),
                ("item/started", "inProgress") | ("item/completed", "completed" | "failed")
            )
            || item.kind != "commandExecution"
            || item.source != "userShell"
        {
            return None;
        }
        uuid(&event.params.thread_id)?;
        uuid(&event.params.turn_id)?;
        if uuid::Uuid::parse_str(uuid(&item.id)?)
            .ok()?
            .get_version_num()
            != 4
        {
            return None;
        }
        Some(event)
    }

    fn role(&self) -> ObservationRole {
        if self.method == "item/started" {
            ObservationRole::Intent
        } else {
            ObservationRole::Result
        }
    }

    fn identity(&self) -> String {
        format!(
            "{}:{}:{}",
            self.params.turn_id, self.params.item.id, self.method
        )
    }

    fn reference(&self) -> String {
        format!(
            "native-user-shell:{}:{}",
            self.params.thread_id,
            self.identity()
        )
    }
}

fn native_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

pub(crate) fn peer_instance(instance: &str) -> Option<&str> {
    let (peer, capture) = instance.rsplit_once(":capture:")?;
    if !native_uuid(capture) {
        return None;
    }
    let mut parts = peer.strip_prefix("native-events:")?.split(':');
    if !native_uuid(parts.next()?) {
        return None;
    }
    for maximum in [u64::MAX, u32::MAX as u64, u64::MAX] {
        let raw = parts.next()?;
        let value = raw.parse::<u64>().ok()?;
        if value == 0 || value > maximum || value.to_string() != raw {
            return None;
        }
    }
    if parts.next().is_some() {
        return None;
    }
    Some(peer)
}

fn native_coordinates<'a>(
    instance: &'a str,
    reference: &'a str,
) -> Option<(&'a str, [&'a str; 3])> {
    let peer = peer_instance(instance)?;
    let mut fields = reference.strip_prefix("native-user-shell:")?.split(':');
    let ids = [fields.next()?, fields.next()?, fields.next()?];
    if !ids.iter().all(|id| native_uuid(id))
        || !matches!(fields.next()?, "item/started" | "item/completed")
        || fields.next().is_some()
    {
        return None;
    }
    Some((peer, ids))
}

fn correlation(
    role: ObservationRole,
    manifest: &str,
    revision: u32,
    reference: &str,
    instance: &str,
) -> Option<HostCorrelationEvidence> {
    let mut evidence = HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: matches!(revision, 4 | 5)
            .then_some(CanonicalEventFamily::OtherExecutable),
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: role,
        field_provenance: if matches!(revision, 4 | 5) {
            vec![CorrelationFieldClaim {
                field: CorrelationField::CanonicalEventFamily,
                source_ref: reference.into(),
                evidence_ref: reference.into(),
            }]
        } else {
            vec![]
        },
        adapter_manifest_ref: manifest.into(),
        adapter_revision: revision,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    };
    if revision == 5 {
        let (peer, [thread, turn, item]) = native_coordinates(instance, reference)?;
        evidence.host_instance_id = Some(peer.into());
        evidence.host_trace_lineage_id = Some(format!("native-thread:{thread}:turn:{turn}"));
        evidence.host_lane_key = Some(format!("native-thread:{thread}"));
        evidence.native_request_id = Some(item.into());
        evidence.field_provenance.push(CorrelationFieldClaim {
            field: CorrelationField::HostInstanceId,
            source_ref: peer.into(),
            evidence_ref: instance.into(),
        });
        for field in [
            CorrelationField::HostTraceLineageId,
            CorrelationField::HostLaneKey,
            CorrelationField::NativeRequestId,
        ] {
            evidence.field_provenance.push(CorrelationFieldClaim {
                field,
                source_ref: reference.into(),
                evidence_ref: reference.into(),
            });
        }
    }
    Some(evidence)
}

/// Recheck the protected original against a reserved live-source envelope at ingestion.
/// This proves neither source origin (sealed ingress does that) nor namespace/Work authority.
/// Historical parser 1/2 records remain metadata-only; parser 3 keeps its unclassified roles.
pub fn record_matches(body: &CaptureRecordBody, protected: &[u8], manifest: &str) -> bool {
    let Some(event) = std::str::from_utf8(protected).ok().and_then(Event::decode) else {
        return false;
    };
    let role = match body.parser_revision {
        1 if body.original_length <= 65_536 => ObservationRole::StateProbe,
        2 => ObservationRole::StateProbe,
        3..=5 => event.role(),
        _ => return false,
    };
    body.adapter_revision == body.parser_revision
        && body.canonicalization_revision == 1
        && body.source_revision.as_str() == SOURCE_REVISION
        && body.source_kind == EvidenceSourceKind::Other
        && body.identity_domain == SOURCE_REVISION
        && body.identity_strength == IdentityStrength::StableNative
        && body.source_session_ref == event.params.thread_id
        && body.source_record_identity.as_str() == event.identity()
        && body.source_ref == event.reference()
        && body.observation_role == role
        && correlation(
            role,
            manifest,
            body.parser_revision,
            &event.reference(),
            body.source_instance_id.as_str(),
        )
        .as_ref()
            == Some(&body.correlation)
        && body.adapter_manifest_ref == manifest
        && body.eligible_event_manifest_ref == ELIGIBLE_EVENTS
        && body.source_role == SourceRole::Host
        && body.content_trust == ContentTrust::Observed
        && body.capture_completeness == CaptureCompleteness::Partial
        && !body.surface_eligible
        && body.source_observation_id_hint.is_none()
        && body.task_id.is_none()
        && body.repository_instance_id.is_none()
        && body.worktree_instance_id.is_none()
        && body.source_sequence_origin == Some(0)
        && body.source_revision_mode == SourceRevisionMode::Append
        && body.previous_source_revision.is_none()
        && body.close_watermark.is_none()
        && body.source_byte_range
            == Some(EvidenceByteRange {
                start: 0,
                end: body.original_length,
            })
        && body.scope_effect_claims.is_empty()
        && body.source_local_evidence.is_none()
        && body.lifecycle.is_none()
        && body.unsupported_record_classification.is_none()
        && body.recovery_preflight.is_none()
}

/// The original async normalizer may consume these facts only as independent weak candidates.
/// Admission already checked the protected original; this does not enable any Host capability.
pub fn is_unqualified_execution(observation: &SourceObservation, receipt: &SourceReceipt) -> bool {
    matches!(
        observation.observation_role,
        ObservationRole::Intent | ObservationRole::Result
    ) && receipt.source_kind == EvidenceSourceKind::Other
        && receipt.source_revision.as_str() == SOURCE_REVISION
        && receipt.identity_domain == SOURCE_REVISION
        && matches!(receipt.parser_revision, 4 | 5)
        && receipt.adapter_revision == receipt.parser_revision
        && receipt.canonicalization_revision == 1
        && receipt.eligible_event_manifest_ref == ELIGIBLE_EVENTS
        && observation.source_receipt_ref == receipt.source_receipt_id
        && observation.source_observation_id == receipt.source_observation_id
        && observation.source_instance_id == receipt.source_instance_id
        && observation.source_revision == receipt.source_revision
        && observation.source_record_identity == receipt.source_record_identity
        && observation.observation_role == receipt.observation_role
        && observation.adapter_revision == receipt.adapter_revision
        && observation.parser_revision == receipt.parser_revision
        && observation.canonicalization_revision == receipt.canonicalization_revision
        && observation.source_role == SourceRole::Host
        && observation.content_trust == ContentTrust::Observed
        && observation.capture_completeness == CaptureCompleteness::Partial
        && correlation(
            observation.observation_role,
            &receipt.adapter_manifest_ref,
            receipt.parser_revision,
            &receipt.source_ref,
            receipt.source_instance_id.as_str(),
        )
        .as_ref()
            == Some(&observation.correlation)
        && observation.scope_effect_claims.is_empty()
        && observation.source_local_evidence.is_none()
        && receipt.lifecycle.is_none()
}

fn observation(raw: &str, instance: &str, sequence: u64, manifest: &str) -> Option<Observation> {
    let event = Event::decode(raw)?;
    let thread = event.params.thread_id.as_str();
    let turn = event.params.turn_id.as_str();
    let item = event.params.item.id.as_str();
    Some(Observation(CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: instance.into(),
        source_revision: SOURCE_REVISION.into(),
        source_record_identity: Some(event.identity()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: SOURCE_REVISION.into(),
        source_ref: event.reference(),
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
        observation_role: event.role(),
        correlation: correlation(event.role(), manifest, 5, &event.reference(), instance)?,
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: false,
        adapter_revision: 5,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
        parser_revision: 5,
        canonicalization_revision: 1,
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw.as_bytes().to_vec(),
    }))
}

fn blocked(error: &WireError) -> bool {
    matches!(error, WireError::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
}

pub(crate) fn execution_observation(
    raw: &str,
    instance: &str,
    sequence: u64,
    manifest: &str,
    revision: u32,
) -> Option<Observation> {
    crate::execution_source::input_revision(raw, instance, sequence, manifest, revision)
        .map(Observation)
}

/// Explicit source connection only. Never start a host, send hidden requests or poll work state.
/// Native JSONRPC text is forwarded unchanged, with stdio's newline framing.
pub fn relay(
    snapshot: RuntimeSnapshot,
    endpoint: &Path,
    manifest: &str,
    execution_manifests: &[(crate::execution_source::Profile, String)],
) -> Result<()> {
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
                    let execution = publisher.execution_profile().and_then(|format| {
                        let (_, manifest) = execution_manifests
                            .iter()
                            .find(|(value, _)| *value == format)?;
                        execution_observation(
                            &text,
                            &instance,
                            sequence,
                            manifest,
                            format.revision(),
                        )
                    });
                    if let Some(observed) =
                        execution.or_else(|| observation(&text, &instance, sequence, manifest))
                    {
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
