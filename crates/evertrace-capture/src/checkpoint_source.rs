//! Fixed metadata measured on the live Host connection. Not original hook output or lane closure.
use evertrace_domain::evidence::{
    CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
    CorrelationField, CorrelationFieldClaim, EvidenceByteRange, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceRevisionMode, SourceRole,
};
use serde::{Deserialize, Serialize};

use crate::{CaptureRecordBody, CaptureRecordInput};

pub const SOURCE_REVISION: &str = "native-hook-checkpoint-metadata-0.166.0-v1";
pub const ADAPTER_VERSION: &str = "native-hook-checkpoint-metadata-0.166.0-v1:capture-1";
pub const ELIGIBLE_EVENTS: &str = "native-hook-checkpoint-metadata-events-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Kind {
    Stop,
    SessionEnd,
    PreCompact,
    PostCompact,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Notification {
    #[serde(default, deserialize_with = "crate::host_events::id_present")]
    id: bool,
    method: String,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    thread_id: String,
    turn_id: Option<String>,
    run: Run,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    event_name: Kind,
    status: String,
}

/// Observer metadata only. No hook output, message text, source path or caller-provided truth.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    thread_id: String,
    turn_id: Option<String>,
    kind: Kind,
}

impl Header {
    pub fn reason(&self) -> evertrace_domain::work::CheckpointReason {
        use evertrace_domain::work::CheckpointReason;
        match self.kind {
            Kind::Stop => CheckpointReason::Stop,
            Kind::SessionEnd => CheckpointReason::SessionEnd,
            Kind::PreCompact | Kind::PostCompact => CheckpointReason::Compact,
        }
    }

    pub fn targets(
        &self,
        trigger: &evertrace_domain::evidence::SourceReceipt,
        physical: &evertrace_domain::evidence::SourceReceipt,
    ) -> bool {
        crate::execution_source::checkpoint_coordinates(physical).is_some_and(
            |(peer, thread, turn)| {
                crate::host_events::peer_instance(trigger.source_instance_id.as_str()) == Some(peer)
                    && self.thread_id == thread
                    // Compaction runs in its own turn; it requests a snapshot of existing thread-bound Work.
                    && (self.kind != Kind::Stop || self.turn_id.as_deref() == Some(turn))
            },
        )
    }

    fn valid(&self) -> bool {
        uuid::Uuid::parse_str(&self.thread_id)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == self.thread_id)
            && self
                .turn_id
                .as_ref()
                .is_none_or(|id| !id.trim().is_empty() && id.len() <= 512)
    }
}

fn correlation(manifest: &str, reference: &str) -> HostCorrelationEvidence {
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: Some(CanonicalEventFamily::Lifecycle),
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: ObservationRole::Lifecycle,
        field_provenance: vec![CorrelationFieldClaim {
            field: CorrelationField::CanonicalEventFamily,
            source_ref: reference.into(),
            evidence_ref: reference.into(),
        }],
        adapter_manifest_ref: manifest.into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn reference(header: &Header, sequence: u64) -> String {
    format!("host-checkpoint-metadata:{}:{sequence}", header.thread_id)
}

pub(crate) fn input(
    raw: &str,
    instance: &str,
    sequence: u64,
    manifest: &str,
) -> Option<CaptureRecordInput> {
    crate::host_events::peer_instance(instance)?;
    let notification: Notification = serde_json::from_str(raw).ok()?;
    if notification.id
        || notification.method != "hook/completed"
        || notification.params.run.status != "completed"
    {
        return None;
    }
    let header = Header {
        thread_id: notification.params.thread_id,
        turn_id: notification.params.turn_id,
        kind: notification.params.run.event_name,
    };
    if !header.valid() {
        return None;
    }
    let payload = serde_json::to_vec(&header).ok()?;
    let reference = reference(&header, sequence);
    Some(CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: instance.into(),
        source_revision: SOURCE_REVISION.into(),
        source_record_identity: Some(sequence.to_string()),
        identity_strength: Some(IdentityStrength::StableSourceSequence),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: SOURCE_REVISION.into(),
        source_ref: reference.clone(),
        session_ref: header.thread_id,
        turn_ref: header.turn_id,
        tool_ref: None,
        source_sequence: sequence,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: Some(EvidenceByteRange {
            start: 0,
            end: payload.len() as u64,
        }),
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Lifecycle,
        correlation: correlation(manifest, &reference),
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: false,
        adapter_revision: 1,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: payload,
    })
}

pub fn observed_request(
    observation: &evertrace_domain::evidence::SourceObservation,
    receipt: &evertrace_domain::evidence::SourceReceipt,
    protected: &[u8],
) -> Option<Header> {
    let header: Header = serde_json::from_slice(protected).ok()?;
    (header.valid()
        && receipt.source_revision.as_str() == SOURCE_REVISION
        && observation.source_receipt_ref == receipt.source_receipt_id
        && observation.source_revision == receipt.source_revision
        && receipt.source_ref == reference(&header, receipt.source_sequence)
        && observation.observation_role == ObservationRole::Lifecycle
        && receipt.lifecycle.is_none()
        && receipt.protected_length == protected.len() as u64)
        .then_some(header)
}

pub fn record_matches(body: &CaptureRecordBody, protected: &[u8], manifest: &str) -> bool {
    let Ok(header) = serde_json::from_slice::<Header>(protected) else {
        return false;
    };
    header.valid()
        && crate::host_events::peer_instance(body.source_instance_id.as_str()).is_some()
        && body.source_revision.as_str() == SOURCE_REVISION
        && body.source_kind == EvidenceSourceKind::Other
        && body.identity_domain == SOURCE_REVISION
        && body.identity_strength == IdentityStrength::StableSourceSequence
        && body.source_session_ref == header.thread_id
        && body.source_record_identity.as_str() == body.source_sequence.to_string()
        && body.source_ref == reference(&header, body.source_sequence)
        && body.observation_role == ObservationRole::Lifecycle
        && body.correlation == correlation(manifest, &body.source_ref)
        && body.adapter_manifest_ref == manifest
        && body.eligible_event_manifest_ref == ELIGIBLE_EVENTS
        && body.adapter_revision == 1
        && body.parser_revision == 1
        && body.canonicalization_revision == 1
        && body.source_role == SourceRole::Host
        && body.content_trust == ContentTrust::Observed
        && body.capture_completeness == CaptureCompleteness::Partial
        && !body.surface_eligible
        && body.source_observation_id_hint.is_none()
        && body.task_id.is_none()
        && body.repository_instance_id.is_none()
        && body.worktree_instance_id.is_none()
        && body.source_sequence_origin.is_none()
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
