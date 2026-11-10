//! Source-owned local spawn/exit receipts. Measurements do not grant namespace or Work authority.
pub mod canary;

use evertrace_domain::evidence::{
    CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
    CorrelationField, CorrelationFieldClaim, EvidenceByteRange, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceObservation, SourceReceipt,
    SourceRevisionMode, SourceRole,
};
use serde::Deserialize;

use crate::{CaptureRecordBody, CaptureRecordInput, host_events};

pub const SOURCE_REVISION: &str = "native-local-execution-0.166.0-v1";
pub const ADAPTER_VERSION: &str = "native-local-execution-0.166.0-v1:capture-6";
pub const QUALIFIED_ADAPTER_VERSION: &str = "native-local-execution-0.166.0-v1:capture-7";
pub const ELIGIBLE_EVENTS: &str = "native-local-execution-events-v1";
pub const REVISION: u32 = 6;
pub const QUALIFIED_REVISION: u32 = 7;
const OBSERVER_CONTEXT_REVISION: u32 = 9;
const CONTEXT_REVISION: u32 = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    ProcessOriginal,
    ProcessNative,
    ObserverContext,
    Context,
}

impl Profile {
    pub fn from_revision(revision: u32) -> Option<Self> {
        match revision {
            REVISION => Some(Self::ProcessOriginal),
            QUALIFIED_REVISION => Some(Self::ProcessNative),
            OBSERVER_CONTEXT_REVISION => Some(Self::ObserverContext),
            CONTEXT_REVISION => Some(Self::Context),
            _ => None,
        }
    }

    pub fn from_adapter_version(version: &str) -> Option<Self> {
        [
            Self::ProcessOriginal,
            Self::ProcessNative,
            Self::ObserverContext,
            Self::Context,
        ]
        .into_iter()
        .find(|profile| profile.adapter_version() == version)
    }

    pub fn revision(self) -> u32 {
        match self {
            Self::ProcessOriginal => REVISION,
            Self::ProcessNative => QUALIFIED_REVISION,
            Self::ObserverContext => OBSERVER_CONTEXT_REVISION,
            Self::Context => CONTEXT_REVISION,
        }
    }

    pub fn source_revision(self) -> &'static str {
        match self {
            Self::ProcessOriginal | Self::ProcessNative => SOURCE_REVISION,
            Self::ObserverContext | Self::Context => "native-local-execution-0.166.0-v2",
        }
    }

    pub fn adapter_version(self) -> &'static str {
        match self {
            Self::ProcessOriginal => ADAPTER_VERSION,
            Self::ProcessNative => QUALIFIED_ADAPTER_VERSION,
            Self::ObserverContext => "native-local-execution-0.166.0-v2:capture-9",
            Self::Context => "native-local-execution-0.166.0-v2:capture-11",
        }
    }

    pub fn native_identity(self) -> bool {
        self != Self::ProcessOriginal
    }

    pub fn has_context(self) -> bool {
        matches!(self, Self::ObserverContext | Self::Context)
    }

    fn sequence_origin(self, sequence: u64) -> Option<u64> {
        if self == Self::Context {
            // Only receipt of the context's first emission witnesses this observer's prefix.
            (sequence == 1).then_some(1)
        } else {
            Some(0)
        }
    }

    pub fn eligible_events(self) -> &'static str {
        match self {
            Self::ProcessOriginal | Self::ProcessNative => ELIGIBLE_EVENTS,
            Self::ObserverContext | Self::Context => "native-local-execution-events-v2",
        }
    }
}

pub fn is_source_revision(revision: &str) -> bool {
    revision == SOURCE_REVISION || revision == Profile::Context.source_revision()
}

pub fn is_qualified_revision(revision: u32) -> bool {
    Profile::from_revision(revision).is_some_and(Profile::native_identity)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    #[serde(default, deserialize_with = "host_events::id_present")]
    id: bool,
    #[serde(default)]
    jsonrpc: Option<String>,
    // The source transport adds a timestamp; it is never an execution identity.
    #[serde(default, rename = "emittedAtMs")]
    _emitted_at_ms: Option<u64>,
    method: String,
    params: Measurement,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Measurement {
    receipt_version: u32,
    #[serde(default, deserialize_with = "present")]
    execution_context_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    lane_sequence: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    working_directory: Option<Option<String>>,
    thread_id: String,
    turn_id: String,
    call_id: String,
    origin: String,
    execution_ordinal: u32,
    phase: String,
    process_pid: Option<u32>,
    process_start_ticks: Option<u64>,
    exit_code: Option<i32>,
}

// Preserve absent versus explicit null, and let the typed decoder reject duplicate fields.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

impl Event {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let event: Self = serde_json::from_slice(bytes).ok()?;
        let value = &event.params;
        if event.id
            || event.jsonrpc.as_deref().is_some_and(|value| value != "2.0")
            || event.method != "item/commandExecution/attempt"
            || !match value.receipt_version {
                1 => {
                    value.execution_context_id.is_none()
                        && value.lane_sequence.is_none()
                        && value.working_directory.is_none()
                }
                2 => {
                    value.execution_context_id.as_deref().is_some_and(uuid)
                        && value.lane_sequence.is_some_and(|value| value > 0)
                        && value.working_directory.as_ref().is_some_and(|path| {
                            path.as_ref().is_none_or(|path| {
                                path.len() <= 4096
                                    && !path.contains('\0')
                                    && std::path::Path::new(path).is_absolute()
                            })
                        })
                }
                _ => false,
            }
            || !uuid(&value.thread_id)
            || !uuid(&value.turn_id)
            || !matches!(value.origin.as_str(), "agent" | "user_shell")
            || value.execution_ordinal == 0
            || !matches!(
                (value.phase.as_str(), value.exit_code),
                ("started", None) | ("exited", Some(0..=255))
            )
            || !matches!(
                (value.process_pid, value.process_start_ticks),
                (None, None) | (Some(1..), Some(1..))
            )
        {
            return None;
        }
        Some(event)
    }

    fn role(&self) -> ObservationRole {
        if self.params.phase == "started" {
            ObservationRole::Intent
        } else {
            ObservationRole::Result
        }
    }

    fn identity(&self) -> String {
        format!("{}:{}", self.params.execution_ordinal, self.params.phase)
    }

    fn accepts(&self, profile: Profile) -> bool {
        (self.params.receipt_version == 2) == profile.has_context()
    }

    fn reference(&self) -> String {
        let context = self
            .params
            .execution_context_id
            .as_ref()
            .map(|id| {
                format!(
                    "{id}:{}:",
                    self.params.lane_sequence.expect("decoded context sequence")
                )
            })
            .unwrap_or_default();
        format!(
            "native-execution:{}:{}:{context}{}",
            self.params.thread_id,
            self.params.turn_id,
            self.identity()
        )
    }
}

struct Coordinates<'a> {
    thread: &'a str,
    turn: &'a str,
    context: Option<(&'a str, u64)>,
    ordinal: u32,
    phase: &'a str,
}

fn coordinates(reference: &str, revision: u32) -> Option<Coordinates<'_>> {
    let format = Profile::from_revision(revision)?;
    let fields = reference
        .strip_prefix("native-execution:")?
        .split(':')
        .collect::<Vec<_>>();
    let (thread, turn, context, ordinal, phase) = match fields.as_slice() {
        [thread, turn, ordinal, phase] if !format.has_context() => {
            (*thread, *turn, None, *ordinal, *phase)
        }
        [thread, turn, context, sequence, ordinal, phase] if format.has_context() => {
            let sequence = sequence.parse::<u64>().ok().filter(|value| *value > 0)?;
            if !uuid(context) {
                return None;
            }
            (*thread, *turn, Some((*context, sequence)), *ordinal, *phase)
        }
        _ => return None,
    };
    if !uuid(thread) || !uuid(turn) {
        return None;
    }
    Some(Coordinates {
        thread,
        turn,
        context,
        ordinal: ordinal.parse::<u32>().ok().filter(|value| *value > 0)?,
        phase,
    })
}

// Scope each observer's source to the native context and its measured counter.
fn source_coordinates(
    instance: &str,
    reference: &str,
    profile: Profile,
    transport_sequence: u64,
) -> Option<(String, u64)> {
    if profile != Profile::Context {
        return Some((instance.into(), transport_sequence));
    }
    let (context, sequence) = coordinates(reference, profile.revision())?.context?;
    let observer = match instance.rsplit_once(":context:") {
        Some((observer, existing)) if existing == context => observer,
        Some(_) => return None,
        None => instance,
    };
    host_events::peer_instance(observer)?;
    Some((format!("{observer}:context:{context}"), sequence))
}

fn lane_key(coordinates: &Coordinates<'_>) -> String {
    let base = format!("native-thread:{}", coordinates.thread);
    match coordinates.context {
        Some((context, _)) => format!("{base}:context:{context}"),
        None => base,
    }
}

fn lifecycle(
    reference: &str,
    manifest: &str,
    revision: u32,
) -> Option<evertrace_domain::work::LaneLifecycleEvidence> {
    use evertrace_domain::work::{LaneLifecycleEvidence, LivenessState};
    let coordinates = coordinates(reference, revision)?;
    let (context, sequence) = coordinates.context?;
    Some(LaneLifecycleEvidence {
        host_session_id: coordinates.thread.into(),
        agent_id: coordinates.thread.into(),
        incarnation_ref: Some(format!("native-context:{context}")),
        host_lane_key: lane_key(&coordinates),
        lane_sequence: sequence,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: Profile::Context.eligible_events().into(),
        child_session_id: None,
        parent_host_lane_key: None,
        spawn_event_ref: None,
        terminal_event_ref: None,
        terminal_kind: None,
        host_final_return: false,
        source_close_ref: None,
        parent_session_end_ref: None,
        liveness_probe_ref: None,
        liveness_state: LivenessState::Unknown,
        delegated_goal_ref: None,
        delegated_target_refs: vec![],
        delegated_acceptance_refs: vec![],
        reasoning_visibility: vec![],
    })
}

fn evidence(
    instance: &str,
    reference: &str,
    manifest: &str,
    role: ObservationRole,
    request: Option<&str>,
    revision: u32,
) -> Option<HostCorrelationEvidence> {
    let coordinates = coordinates(reference, revision)?;
    let observer = if Profile::from_revision(revision)? == Profile::Context {
        let (observer, context) = instance.rsplit_once(":context:")?;
        if coordinates.context?.0 != context {
            return None;
        }
        observer
    } else {
        instance
    };
    let peer = host_events::peer_instance(observer)?;
    if !matches!(
        (coordinates.phase, role),
        ("started", ObservationRole::Intent) | ("exited", ObservationRole::Result)
    ) {
        return None;
    }
    let mut fields = vec![
        CorrelationField::CanonicalEventFamily,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    if request.is_some() {
        fields.push(CorrelationField::NativeRequestId);
    }
    let mut claims = fields
        .into_iter()
        .map(|field| CorrelationFieldClaim {
            field,
            source_ref: reference.into(),
            evidence_ref: reference.into(),
        })
        .collect::<Vec<_>>();
    claims.push(CorrelationFieldClaim {
        field: CorrelationField::HostInstanceId,
        source_ref: peer.into(),
        evidence_ref: instance.into(),
    });
    Some(HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: Some(peer.into()),
        host_trace_lineage_id: Some(format!(
            "native-thread:{}:turn:{}",
            coordinates.thread, coordinates.turn
        )),
        host_lane_key: Some(lane_key(&coordinates)),
        canonical_event_family: Some(CanonicalEventFamily::OtherExecutable),
        native_request_id: request.map(str::to_owned),
        physical_execution_ordinal: Some(coordinates.ordinal),
        pairing_role: role,
        field_provenance: claims,
        adapter_manifest_ref: manifest.into(),
        adapter_revision: revision,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    })
}

fn request_id(value: &str) -> Option<&str> {
    // Read only after protection; redaction tokens and unsupported identifiers never become keys.
    (!value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(value)
}

pub(crate) fn input_revision(
    raw: &str,
    instance: &str,
    sequence: u64,
    manifest: &str,
    revision: u32,
) -> Option<CaptureRecordInput> {
    let format = Profile::from_revision(revision)?;
    let event = Event::decode(raw.as_bytes())?;
    if !event.accepts(format) {
        return None;
    }
    let reference = event.reference();
    let (instance, sequence) = source_coordinates(instance, &reference, format, sequence)?;
    Some(CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: instance.clone(),
        source_revision: format.source_revision().into(),
        source_record_identity: Some(event.identity()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: format.source_revision().into(),
        source_ref: reference.clone(),
        session_ref: event.params.thread_id.clone(),
        turn_ref: Some(event.params.turn_id.clone()),
        tool_ref: None,
        source_sequence: sequence,
        source_sequence_origin: format.sequence_origin(sequence),
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
        correlation: evidence(
            &instance,
            &reference,
            manifest,
            event.role(),
            None,
            revision,
        )?,
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: lifecycle(&reference, manifest, revision),
        unsupported_record_classification: None,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: false,
        adapter_revision: revision,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: format.eligible_events().into(),
        parser_revision: revision,
        canonicalization_revision: 1,
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw.as_bytes().to_vec(),
    })
}

pub(crate) fn protected_correlation(
    input: &CaptureRecordInput,
    bytes: &[u8],
) -> Option<HostCorrelationEvidence> {
    let event = Event::decode(bytes)?;
    if !event.accepts(Profile::from_revision(input.adapter_revision)?)
        || input.source_ref != event.reference()
        || input.source_record_identity.as_deref() != Some(&event.identity())
    {
        return None;
    }
    evidence(
        &input.source_instance_id,
        &input.source_ref,
        &input.adapter_manifest_ref,
        input.observation_role,
        request_id(&event.params.call_id),
        input.adapter_revision,
    )
}

/// Decode measurements only; this does not admit a source or enable a correlation gate.
pub fn protected_measurement(
    protected: &[u8],
    instance: &str,
    manifest: &str,
    revision: u32,
) -> Option<(String, HostCorrelationEvidence)> {
    let format = Profile::from_revision(revision)?;
    let event = Event::decode(protected)?;
    if !event.accepts(format) {
        return None;
    }
    let reference = event.reference();
    let (instance, _) = source_coordinates(instance, &reference, format, 0)?;
    let correlation = evidence(
        &instance,
        &reference,
        manifest,
        event.role(),
        request_id(&event.params.call_id),
        revision,
    )?;
    Some((reference, correlation))
}

pub fn record_matches(body: &CaptureRecordBody, protected: &[u8], manifest: &str) -> bool {
    let Some(raw) = std::str::from_utf8(protected).ok() else {
        return false;
    };
    let Some(expected) = input_revision(
        raw,
        body.source_instance_id.as_str(),
        body.source_sequence,
        manifest,
        body.parser_revision,
    ) else {
        return false;
    };
    body.source_instance_id.as_str() == expected.source_instance_id
        && body.source_sequence == expected.source_sequence
        && body.source_revision.as_str() == expected.source_revision
        && body.source_kind == expected.source_kind
        && body.identity_domain == expected.identity_domain
        && body.identity_strength == IdentityStrength::StableNative
        && body.source_record_identity.as_str()
            == expected.source_record_identity.as_deref().unwrap_or("")
        && body.source_ref == expected.source_ref
        && body.source_session_ref == expected.session_ref
        && body.observation_role == expected.observation_role
        && protected_correlation(&expected, protected).as_ref() == Some(&body.correlation)
        && body.adapter_revision == expected.adapter_revision
        && body.parser_revision == expected.parser_revision
        && body.canonicalization_revision == 1
        && body.adapter_manifest_ref == manifest
        && body.eligible_event_manifest_ref == expected.eligible_event_manifest_ref
        && body.source_role == SourceRole::Host
        && body.content_trust == ContentTrust::Observed
        && body.capture_completeness == CaptureCompleteness::Partial
        && !body.surface_eligible
        && body.source_observation_id_hint.is_none()
        && body.task_id.is_none()
        && body.repository_instance_id.is_none()
        && body.worktree_instance_id.is_none()
        && body.source_sequence_origin == expected.source_sequence_origin
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
        && body.lifecycle == expected.lifecycle
        && body.unsupported_record_classification.is_none()
        && body.recovery_preflight.is_none()
}

/// Canonical observations may retain a namespace admitted by the original ingestion command.
pub fn is_execution(observation: &SourceObservation, receipt: &SourceReceipt) -> bool {
    let Some(format) = Profile::from_revision(receipt.parser_revision) else {
        return false;
    };
    let mut correlation = observation.correlation.clone();
    if is_qualified_revision(receipt.parser_revision)
        && correlation.admission == CorrelationAdmission::ExactCapable
    {
        if correlation.exact_key().is_none() || correlation.validate().is_err() {
            return false;
        }
        correlation.admission = CorrelationAdmission::Unavailable;
        correlation.strong_gate_receipt_ref = None;
    }
    let source_matches = format != Profile::Context
        || source_coordinates(
            receipt.source_instance_id.as_str(),
            &receipt.source_ref,
            format,
            receipt.source_sequence,
        )
        .is_some_and(|(instance, sequence)| {
            instance == receipt.source_instance_id.as_str() && sequence == receipt.source_sequence
        });
    source_matches
        && receipt.source_sequence_origin == format.sequence_origin(receipt.source_sequence)
        && receipt.source_revision.as_str() == format.source_revision()
        && receipt.identity_domain == format.source_revision()
        && receipt.source_kind == EvidenceSourceKind::Other
        && receipt.adapter_revision == receipt.parser_revision
        && receipt.canonicalization_revision == 1
        && receipt.eligible_event_manifest_ref == format.eligible_events()
        && observation.source_receipt_ref == receipt.source_receipt_id
        && observation.source_observation_id == receipt.source_observation_id
        && observation.source_instance_id == receipt.source_instance_id
        && observation.source_revision == receipt.source_revision
        && observation.source_record_identity == receipt.source_record_identity
        && observation.observation_role == receipt.observation_role
        && observation.adapter_revision == receipt.parser_revision
        && observation.parser_revision == receipt.parser_revision
        && observation.canonicalization_revision == 1
        && observation.source_role == SourceRole::Host
        && observation.content_trust == ContentTrust::Observed
        && observation.capture_completeness == CaptureCompleteness::Partial
        && evidence(
            receipt.source_instance_id.as_str(),
            &receipt.source_ref,
            &receipt.adapter_manifest_ref,
            receipt.observation_role,
            observation.correlation.native_request_id.as_deref(),
            receipt.parser_revision,
        )
        .as_ref()
            == Some(&correlation)
        && observation.scope_effect_claims.is_empty()
        && observation.source_local_evidence.is_none()
        && receipt.lifecycle
            == lifecycle(
                &receipt.source_ref,
                &receipt.adapter_manifest_ref,
                receipt.parser_revision,
            )
}
