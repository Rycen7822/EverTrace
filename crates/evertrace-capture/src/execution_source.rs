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
            || value.receipt_version != 1
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

    fn reference(&self) -> String {
        format!(
            "native-execution:{}:{}:{}",
            self.params.thread_id,
            self.params.turn_id,
            self.identity()
        )
    }
}

fn evidence(
    instance: &str,
    reference: &str,
    manifest: &str,
    role: ObservationRole,
    request: Option<&str>,
    revision: u32,
) -> Option<HostCorrelationEvidence> {
    let peer = host_events::peer_instance(instance)?;
    let fields: Vec<_> = reference
        .strip_prefix("native-execution:")?
        .split(':')
        .collect();
    let [thread, turn, ordinal, phase] = fields.as_slice() else {
        return None;
    };
    let ordinal = ordinal.parse::<u32>().ok().filter(|value| *value > 0)?;
    if !uuid(thread)
        || !uuid(turn)
        || !matches!(
            (*phase, role),
            ("started", ObservationRole::Intent) | ("exited", ObservationRole::Result)
        )
    {
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
        host_trace_lineage_id: Some(format!("native-thread:{thread}:turn:{turn}")),
        host_lane_key: Some(format!("native-thread:{thread}")),
        canonical_event_family: Some(CanonicalEventFamily::OtherExecutable),
        native_request_id: request.map(str::to_owned),
        physical_execution_ordinal: Some(ordinal),
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

pub(crate) fn input(
    raw: &str,
    instance: &str,
    sequence: u64,
    manifest: &str,
) -> Option<CaptureRecordInput> {
    input_revision(raw, instance, sequence, manifest, REVISION)
}

pub(crate) fn input_revision(
    raw: &str,
    instance: &str,
    sequence: u64,
    manifest: &str,
    revision: u32,
) -> Option<CaptureRecordInput> {
    if !matches!(revision, REVISION | QUALIFIED_REVISION) {
        return None;
    }
    let event = Event::decode(raw.as_bytes())?;
    Some(CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: instance.into(),
        source_revision: SOURCE_REVISION.into(),
        source_record_identity: Some(event.identity()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: SOURCE_REVISION.into(),
        source_ref: event.reference(),
        session_ref: event.params.thread_id.clone(),
        turn_ref: Some(event.params.turn_id.clone()),
        tool_ref: None,
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
        correlation: evidence(
            instance,
            &event.reference(),
            manifest,
            event.role(),
            None,
            revision,
        )?,
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: false,
        adapter_revision: revision,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
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
    if input.source_ref != event.reference()
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
    if !matches!(revision, REVISION | QUALIFIED_REVISION) {
        return None;
    }
    let event = Event::decode(protected)?;
    let reference = event.reference();
    let correlation = evidence(
        instance,
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
    body.source_revision.as_str() == SOURCE_REVISION
        && body.source_kind == expected.source_kind
        && body.identity_domain == SOURCE_REVISION
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

/// Canonical observations may retain a namespace admitted by the original ingestion command.
pub fn is_execution(observation: &SourceObservation, receipt: &SourceReceipt) -> bool {
    let mut correlation = observation.correlation.clone();
    if receipt.parser_revision == QUALIFIED_REVISION
        && correlation.admission == CorrelationAdmission::ExactCapable
    {
        if correlation.exact_key().is_none() || correlation.validate().is_err() {
            return false;
        }
        correlation.admission = CorrelationAdmission::Unavailable;
        correlation.strong_gate_receipt_ref = None;
    }
    receipt.source_revision.as_str() == SOURCE_REVISION
        && receipt.identity_domain == SOURCE_REVISION
        && receipt.source_kind == EvidenceSourceKind::Other
        && matches!(receipt.parser_revision, REVISION | QUALIFIED_REVISION)
        && receipt.adapter_revision == receipt.parser_revision
        && receipt.canonicalization_revision == 1
        && receipt.eligible_event_manifest_ref == ELIGIBLE_EVENTS
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
        && receipt.lifecycle.is_none()
}
