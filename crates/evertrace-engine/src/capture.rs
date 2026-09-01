use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use evertrace_capture::{
    CasDigest, CasStore, DurableSpool, PendingGapMarker, PendingQuarantine, RuntimeSnapshot,
    SealedFrame, decode_validated_record_body,
};
use evertrace_codex::{
    adapter_manifest::{
        AdapterCapabilityManifest, AdmissionFailureObservability as ManifestObservability,
        CaptureGuarantee, ObservableCapability,
    },
    source_catalog::compile_capture_contract,
};
use evertrace_domain::evidence::{
    CaptureGapMarkerEvidence, CaptureOutageInterval, CaptureOutagePositiveSource,
    EvidenceByteRange, EvidenceSurface, IdentityStrength, ObservationRole,
    ReconciliationProvenance, SourceArchiveMode, SourceInstanceId, SourceObservation,
    SourceReceipt, SourceRevision, hex, payload_fingerprint, source_receipt_id,
};
use evertrace_domain::ids::{
    CaptureOutageIntervalId, CaptureReceiptId, CommandId, ExecutionLaneId, SourceObservationId,
};
use evertrace_domain::work::{
    AdmissionFailureObservability, CaptureReceipt, CaptureResolverInput, CoverageLevel,
    ExecutionLane, LivenessState, SequenceGap, resolve_capture,
};
use evertrace_store::search::build_evidence_surface;
use evertrace_store::{
    DirtyTargetKind, EventScope,
    IndependentSourceReconciliation as StoreIndependentSourceReconciliation, JournalCommand,
    JournalEventDraft, JournalPayload, NamedCurrentDependency, NormalizationWatermark,
    ReconciliationArtifactDescriptor, ReconciliationArtifactKind, ReconciliationArtifactOwnership,
    ReconciliationFrontier, SourceCloseRange, SourceCloseReconciliation, SourceKind,
};
use serde::Serialize;
use thiserror::Error;

use crate::{WriterActorError, WriterHandle, ingest::IngestError};

#[derive(Clone)]
pub(crate) struct VerifiedCapture {
    pub body: evertrace_capture::CaptureRecordBody,
    pub receipt: SourceReceipt,
    pub observation: SourceObservation,
    pub surface: Option<EvidenceSurface>,
}

pub(crate) fn verify_capture_frame(
    frame: &SealedFrame,
    cas: &CasStore,
) -> Result<VerifiedCapture, IngestError> {
    let (body, observation_id) =
        decode_validated_record_body(&frame.record).map_err(|error| match error {
            evertrace_capture::SpoolFrameError::LegacyUnsupported => IngestError::LegacyRecord,
            evertrace_capture::SpoolFrameError::Corrupt => IngestError::IdentityMismatch,
            _ => IngestError::InvalidRecord,
        })?;
    let cas_digest = CasDigest::from_str(&body.cas_ref).map_err(|_| IngestError::Cas)?;
    let protected = cas.read(&cas_digest).map_err(|_| IngestError::Cas)?;
    if u64::try_from(protected.len()).map_err(|_| IngestError::InvalidRecord)?
        != body.protected_length
        || CasDigest::for_protected_bytes(&protected) != cas_digest
        || body.detector_revision != evertrace_capture::protect::DETECTOR_REVISION
        || body.redaction_revision != evertrace_capture::protect::REDACTION_REVISION
        || (body.archive_mode == SourceArchiveMode::Redacted
            && protected
                .windows(b"[REDACTED]".len())
                .filter(|window| *window == b"[REDACTED]")
                .count()
                < body.redaction_spans.len())
    {
        return Err(IngestError::CasMismatch);
    }
    let secret_digest = body
        .protected_secret_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    let receipt_id = source_receipt_id(
        &body.source_instance_id,
        &body.source_revision,
        &body.source_record_identity,
    )
    .map_err(|_| IngestError::InvalidRecord)?;
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: body.source_instance_id.clone(),
        source_kind: body.source_kind,
        identity_domain: body.identity_domain.clone(),
        source_ref: body.source_ref.clone(),
        source_session_ref: body.source_session_ref.clone(),
        source_revision: body.source_revision.clone(),
        source_record_identity: body.source_record_identity.clone(),
        identity_strength: body.identity_strength,
        source_sequence: body.source_sequence,
        source_sequence_origin: body.source_sequence_origin,
        task_id: body.task_id,
        repository_instance_id: body.repository_instance_id,
        worktree_instance_id: body.worktree_instance_id,
        source_byte_range: body.source_byte_range.clone(),
        spool_byte_range: EvidenceByteRange {
            start: frame.byte_start,
            end: frame.byte_end,
        },
        source_revision_mode: body.source_revision_mode,
        previous_source_revision: body.previous_source_revision.clone(),
        close_watermark: body.close_watermark,
        observation_role: body.observation_role,
        unsupported_record_classification: body.unsupported_record_classification,
        capture_completeness: body.capture_completeness,
        archive_mode: body.archive_mode,
        cas_ref: body.cas_ref.clone(),
        protected_length: body.protected_length,
        original_length: body.original_length,
        protected_secret_digest: body.protected_secret_digest.clone(),
        redaction_spans: body.redaction_spans.clone(),
        adapter_revision: body.adapter_revision,
        adapter_manifest_ref: body.adapter_manifest_ref.clone(),
        eligible_event_manifest_ref: body.eligible_event_manifest_ref.clone(),
        parser_revision: body.parser_revision,
        canonicalization_revision: body.canonicalization_revision,
        detector_revision: body.detector_revision,
        redaction_revision: body.redaction_revision,
        protection_key_generation: body.protection_key_generation,
        event_time_us: body.event_time_us,
        recorded_at_us: body.recorded_at_us,
        lifecycle: body.lifecycle.clone(),
    };
    receipt.validate().map_err(|_| IngestError::InvalidRecord)?;
    let fingerprint =
        payload_fingerprint(body.canonicalization_revision, &protected, secret_digest)
            .map_err(|_| IngestError::InvalidRecord)?;
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: body.source_instance_id.clone(),
        source_revision: body.source_revision.clone(),
        source_record_identity: body.source_record_identity.clone(),
        observation_role: body.observation_role,
        identity_strength: body.identity_strength,
        payload_fingerprint: hex(&fingerprint),
        source_receipt_ref: receipt_id,
        source_role: body.source_role,
        content_trust: body.content_trust,
        capture_completeness: body.capture_completeness,
        adapter_revision: body.adapter_revision,
        parser_revision: body.parser_revision,
        canonicalization_revision: body.canonicalization_revision,
        detector_revision: body.detector_revision,
        redaction_revision: body.redaction_revision,
        correlation: body.correlation.clone(),
        scope_effect_claims: body.scope_effect_claims.clone(),
    };
    observation
        .validate()
        .map_err(|_| IngestError::InvalidRecord)?;
    let surface = build_evidence_surface(&receipt, &observation, &protected, body.surface_eligible)
        .map_err(|_| IngestError::InvalidRecord)?;
    Ok(VerifiedCapture {
        body,
        receipt,
        observation,
        surface,
    })
}

fn parse_digest(value: &str) -> Result<[u8; 32], IngestError> {
    if value.len() != 64 {
        return Err(IngestError::InvalidRecord);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| IngestError::InvalidRecord)?;
        digest[index] = u8::from_str_radix(pair, 16).map_err(|_| IngestError::InvalidRecord)?;
    }
    Ok(digest)
}

const MAX_RECONCILE_ITEMS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LivenessObservation {
    pub host_session_id: String,
    pub agent_id: String,
    pub host_lane_key: String,
    pub incarnation_ref: String,
    pub state: LivenessState,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledEvidence {
    pub evidence_id: String,
    pub reconciliation_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependentSourceReconciliation {
    pub host_session_id: String,
    pub agent_id: String,
    pub host_lane_key: String,
    pub incarnation_ref: String,
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone)]
pub struct ReconcileInput {
    pub runtime_snapshot: RuntimeSnapshot,
    pub adapter_manifests: Vec<AdapterCapabilityManifest>,
    pub liveness: Vec<LivenessObservation>,
    pub reconciled_gaps: Vec<ReconciledEvidence>,
    pub reconciled_outages: Vec<ReconciledEvidence>,
    pub independent_source_reconciliations: Vec<IndependentSourceReconciliation>,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: String,
    pub occurred_at_us: i64,
    pub max_items: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReconcileProgress {
    pub inspected_source_receipts: usize,
    pub lanes_considered: usize,
    pub lane_revisions_recorded: usize,
    pub receipt_revisions_recorded: usize,
    pub gap_revisions_recorded: usize,
    pub outage_revisions_recorded: usize,
    pub operation_successors_recorded: usize,
    pub physical_normalization_recorded: usize,
    pub markers_acknowledged: usize,
    pub quarantine_acknowledged: usize,
    pub replayed: bool,
    pub no_delta: bool,
    pub frontier: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReconcileError {
    #[error("capture reconciliation input is invalid")]
    InvalidInput,
    #[error("capture reconciliation spool state is invalid")]
    Spool,
    #[error("capture reconciliation current projection is invalid")]
    Projection,
    #[error("capture reconciliation manifest contract is missing or invalid")]
    Manifest,
    #[error("capture reconciliation domain state is invalid")]
    Domain,
    #[error("capture reconciliation journal commit failed")]
    Commit,
    #[error("capture reconciliation frontier changed; retry from a fresh snapshot")]
    StaleFrontier,
    #[error("capture reconciliation acknowledgement failed")]
    Acknowledgement,
}

pub async fn reconcile_once(
    input: ReconcileInput,
    writer: &WriterHandle,
) -> Result<ReconcileProgress, ReconcileError> {
    reconcile_selected(input, writer, None).await
}

pub async fn reconcile_observations_once(
    input: ReconcileInput,
    writer: &WriterHandle,
    observation_ids: &[SourceObservationId],
) -> Result<ReconcileProgress, ReconcileError> {
    if observation_ids.is_empty()
        || observation_ids.len() > 16
        || observation_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != observation_ids.len()
    {
        return Err(ReconcileError::InvalidInput);
    }
    reconcile_selected(input, writer, Some(observation_ids)).await
}

async fn reconcile_selected(
    input: ReconcileInput,
    writer: &WriterHandle,
    observation_ids: Option<&[SourceObservationId]>,
) -> Result<ReconcileProgress, ReconcileError> {
    validate_reconcile_input(&input)?;
    let targeted = observation_ids.is_some();
    if targeted
        && (!input.reconciled_gaps.is_empty()
            || !input.reconciled_outages.is_empty()
            || !input.independent_source_reconciliations.is_empty())
    {
        return Err(ReconcileError::InvalidInput);
    }
    let (spool, _) = DurableSpool::open(
        input.runtime_snapshot.spool_dir.clone(),
        input
            .runtime_snapshot
            .spool_limits()
            .map_err(|_| ReconcileError::InvalidInput)?,
    )
    .map_err(|_| ReconcileError::Spool)?;
    let marker_handles = if targeted {
        Vec::new()
    } else {
        spool
            .pending_gap_marker_handles(input.runtime_snapshot.emergency_slots as usize)
            .map_err(|_| ReconcileError::Spool)?
    };
    let dirty_frontier = if let Some(observation_ids) = observation_ids {
        writer
            .project()
            .await
            .map_err(map_reconcile_writer)?
            .reconciliation_frontier_for_observations(observation_ids)
            .map_err(|_| ReconcileError::Projection)?
    } else {
        writer
            .reconciliation_frontier(input.max_items)
            .await
            .map_err(map_reconcile_writer)?
    };
    let quarantine_start = dirty_frontier.frontier.wrapping_add(
        u64::try_from(input.occurred_at_us).map_err(|_| ReconcileError::InvalidInput)?,
    );
    let quarantine_handles = if targeted {
        Vec::new()
    } else {
        spool
            .pending_quarantine_from(MAX_RECONCILE_ITEMS, quarantine_start)
            .map_err(|_| ReconcileError::Spool)?
    };
    let filesystem_descriptors =
        filesystem_artifact_descriptors(&marker_handles, &quarantine_handles)?;
    let mut lookup_descriptors = filesystem_descriptors.clone();
    let mut reconciled_gaps = input.reconciled_gaps.iter().collect::<Vec<_>>();
    reconciled_gaps.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    lookup_descriptors.extend(
        reconciled_gaps
            .into_iter()
            .take(input.max_items)
            .map(|value| ReconciliationArtifactDescriptor {
                kind: ReconciliationArtifactKind::GapMarker,
                artifact_id: format!("gap-reconciliation:{}", value.evidence_id),
                marker_id: Some(value.evidence_id.clone()),
                redacted_fingerprint: None,
                session_ref: None,
                source_ref: None,
            }),
    );
    let remaining_reconciliations = input
        .max_items
        .saturating_sub(input.reconciled_gaps.len().min(input.max_items));
    let mut reconciled_outages = input.reconciled_outages.iter().collect::<Vec<_>>();
    reconciled_outages.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    lookup_descriptors.extend(
        reconciled_outages
            .into_iter()
            .take(remaining_reconciliations)
            .map(|value| ReconciliationArtifactDescriptor {
                kind: ReconciliationArtifactKind::Outage,
                artifact_id: value.evidence_id.clone(),
                marker_id: None,
                redacted_fingerprint: None,
                session_ref: None,
                source_ref: None,
            }),
    );
    let artifact_frontier = if lookup_descriptors.is_empty() {
        None
    } else {
        Some(
            writer
                .reconciliation_artifact_context(
                    lookup_descriptors.clone(),
                    lookup_descriptors.len(),
                )
                .await
                .map_err(map_reconcile_writer)?,
        )
    };
    if artifact_frontier
        .as_ref()
        .is_some_and(|frontier| frontier.frontier != dirty_frontier.frontier)
    {
        return Err(ReconcileError::StaleFrontier);
    }
    let mut dependencies = dirty_frontier
        .items
        .iter()
        .flat_map(|item| item.dependencies.clone())
        .collect::<Vec<_>>();
    if let Some(frontier) = &artifact_frontier {
        if frontier
            .contexts
            .iter()
            .any(|context| context.ownership == ReconciliationArtifactOwnership::Conflict)
        {
            return Err(ReconcileError::Projection);
        }
        dependencies.extend(
            frontier
                .contexts
                .iter()
                .flat_map(|context| context.dependencies.clone()),
        );
    }
    let mut state = CurrentCaptureState::from_dependencies(dependencies)?;
    let mut remaining = input.max_items;
    let manifests = input
        .adapter_manifests
        .iter()
        .map(|manifest| (manifest.adapter_manifest_id.clone(), manifest))
        .collect::<BTreeMap<_, _>>();
    let mut progress = ReconcileProgress {
        inspected_source_receipts: state.source_receipts.len(),
        frontier: dirty_frontier.frontier,
        ..ReconcileProgress::default()
    };
    let mut payloads = Vec::new();
    let mut pending_marker_ids = Vec::new();
    import_emergency_markers(
        &marker_handles,
        &mut state,
        &input,
        &mut payloads,
        &mut pending_marker_ids,
        &mut progress,
        &mut remaining,
    )?;
    let mut pending_quarantine_ids = Vec::new();
    import_quarantine(
        &quarantine_handles,
        &mut state,
        &input,
        &mut payloads,
        &mut pending_quarantine_ids,
        &mut progress,
        &mut remaining,
    )?;
    let explicit_targets = apply_reconciled_evidence(
        &input,
        &mut state,
        &mut payloads,
        &mut progress,
        &mut remaining,
    )?;
    let source_receipts = state.source_receipts.clone();
    let groups = lane_groups(&source_receipts)?;
    let lane_ids = lane_ids_for_groups(&groups, &state)?;
    let mut selected = dirty_rows(&dirty_frontier, remaining);
    remaining = remaining.saturating_sub(selected.len());
    normalize_selected_dirty(&selected, &mut state, &mut payloads, &mut progress)?;
    selected.retain(|dirty| dirty.target_kind == DirtyTargetKind::CaptureReconciliation);
    reconcile_lane_groups(
        LaneReconcileContext {
            input: &input,
            manifests: &manifests,
            groups: &groups,
            lane_ids: &lane_ids,
            selected_dirty: &selected,
            explicit_targets: &explicit_targets,
            pending_marker_ids: &pending_marker_ids,
            pending_quarantine_ids: &pending_quarantine_ids,
        },
        &mut state,
        &mut payloads,
        &mut progress,
        &mut remaining,
    )?;
    let committed = if payloads.is_empty() {
        None
    } else {
        let command = reconciliation_command(&input, payloads)?;
        Some(
            writer
                .commit_if_frontier(command, input.occurred_at_us, dirty_frontier.frontier)
                .await
                .map_err(map_reconcile_writer)?,
        )
    };
    let after_dirty = if let Some(observation_ids) = observation_ids {
        writer
            .project()
            .await
            .map_err(map_reconcile_writer)?
            .reconciliation_frontier_for_observations(observation_ids)
            .map_err(|_| ReconcileError::Projection)?
    } else {
        writer
            .reconciliation_frontier(1)
            .await
            .map_err(map_reconcile_writer)?
    };
    let after_artifacts = if filesystem_descriptors.is_empty() {
        None
    } else {
        Some(
            writer
                .reconciliation_artifact_context(
                    filesystem_descriptors.clone(),
                    filesystem_descriptors.len(),
                )
                .await
                .map_err(map_reconcile_writer)?,
        )
    };
    progress.frontier = after_artifacts
        .as_ref()
        .map_or(after_dirty.frontier, |value| value.frontier);
    progress.replayed = committed.as_ref().is_some_and(|value| value.replayed);
    progress.no_delta = committed.is_none();
    let projected_state = CurrentCaptureState::from_dependencies(
        after_artifacts
            .iter()
            .flat_map(|frontier| &frontier.contexts)
            .flat_map(|context| context.dependencies.clone()),
    )?;
    for handle in marker_handles {
        let marker_id = handle.marker().marker_id.clone();
        if gap_was_propagated(&projected_state, &marker_id) {
            spool
                .acknowledge_gap_marker_handle(handle)
                .map_err(|_| ReconcileError::Acknowledgement)?;
            progress.markers_acknowledged += 1;
        }
    }
    for (handle, marker_id) in quarantine_handles.into_iter().zip(pending_quarantine_ids) {
        if gap_was_propagated(&projected_state, &marker_id) {
            spool
                .acknowledge_quarantine(handle)
                .map_err(|_| ReconcileError::Acknowledgement)?;
            progress.quarantine_acknowledged += 1;
        }
    }
    Ok(progress)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LaneIdentityKey {
    host_session_id: String,
    agent_id: String,
    host_lane_key: String,
}

impl LaneIdentityKey {
    fn from_lifecycle(value: &evertrace_domain::work::LaneLifecycleEvidence) -> Self {
        Self {
            host_session_id: value.host_session_id.clone(),
            agent_id: value.agent_id.clone(),
            host_lane_key: value.host_lane_key.clone(),
        }
    }

    fn from_lane(value: &ExecutionLane) -> Self {
        Self {
            host_session_id: value.host_session_id.clone(),
            agent_id: value.agent_id.clone(),
            host_lane_key: value.host_lane_key.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LaneIncarnationKey {
    identity: LaneIdentityKey,
    incarnation_ref: String,
}

#[derive(Clone)]
struct DirtyRow {
    source_event_seq: u64,
    target_kind: DirtyTargetKind,
    target_id: String,
    dependencies: Vec<NamedCurrentDependency>,
}

#[derive(Default)]
struct CurrentCaptureState {
    source_receipts: Vec<SourceReceipt>,
    source_receipt_event_seq: BTreeMap<SourceObservationId, u64>,
    source_observations: BTreeMap<SourceObservationId, SourceObservation>,
    host_occurrences: Vec<evertrace_domain::evidence::HostOccurrence>,
    operations: Vec<evertrace_domain::evidence::Operation>,
    scope_effects: Vec<evertrace_domain::evidence::ScopeEffect>,
    normalization_watermarks: BTreeSet<evertrace_domain::ids::SourceObservationId>,
    execution_lanes: BTreeMap<ExecutionLaneId, ExecutionLane>,
    execution_lane_event_seq: BTreeMap<ExecutionLaneId, u64>,
    capture_receipts: BTreeMap<ExecutionLaneId, CaptureReceipt>,
    capture_gaps: BTreeMap<String, CaptureGapMarkerEvidence>,
    capture_outages: BTreeMap<CaptureOutageIntervalId, CaptureOutageInterval>,
    source_close_reconciliations: BTreeMap<String, SourceCloseReconciliation>,
}

impl CurrentCaptureState {
    fn from_dependencies(
        dependencies: impl IntoIterator<Item = NamedCurrentDependency>,
    ) -> Result<Self, ReconcileError> {
        let mut state = Self::default();
        let mut unique = BTreeMap::new();
        for dependency in dependencies {
            if let Some(previous) = unique.insert(dependency.row_id.clone(), dependency.clone())
                && previous != dependency
            {
                return Err(ReconcileError::Projection);
            }
        }
        for dependency in unique.into_values() {
            match dependency.payload {
                JournalPayload::SourceReceiptRecorded(value) => {
                    state
                        .source_receipt_event_seq
                        .insert(value.source_observation_id, dependency.source_event_seq);
                    state.source_receipts.push(*value);
                }
                JournalPayload::SourceObservationRecorded(value) => {
                    state
                        .source_observations
                        .insert(value.source_observation_id, *value);
                }
                JournalPayload::OperationDerived(value) => state.operations.push(*value),
                JournalPayload::HostOccurrenceNormalized(value) => {
                    state.host_occurrences.push(*value);
                }
                JournalPayload::ScopeEffectDerived(value) => state.scope_effects.push(*value),
                JournalPayload::NormalizationWatermark(value) => {
                    state
                        .normalization_watermarks
                        .insert(value.source_observation_id);
                }
                JournalPayload::ExecutionLaneRecorded(value) => {
                    state
                        .execution_lane_event_seq
                        .insert(value.execution_lane_id, dependency.source_event_seq);
                    state
                        .execution_lanes
                        .insert(value.execution_lane_id, *value);
                }
                JournalPayload::CaptureReceiptRecorded(value) => {
                    state
                        .capture_receipts
                        .insert(value.execution_lane_id, *value);
                }
                JournalPayload::CaptureGapMarkerRecorded(value) => {
                    state.capture_gaps.insert(value.marker_id.clone(), *value);
                }
                JournalPayload::CaptureOutageIntervalRecorded(value) => {
                    state
                        .capture_outages
                        .insert(value.capture_outage_interval_id, *value);
                }
                JournalPayload::SourceCloseReconciliation(value) => {
                    state
                        .source_close_reconciliations
                        .insert(value.reconciliation_ref.clone(), value);
                }
                _ => {}
            }
        }
        Ok(state)
    }
}

fn filesystem_artifact_descriptors(
    markers: &[PendingGapMarker],
    quarantines: &[PendingQuarantine],
) -> Result<Vec<ReconciliationArtifactDescriptor>, ReconcileError> {
    let mut descriptors = Vec::with_capacity(markers.len() + quarantines.len());
    for handle in markers {
        let marker = handle.marker();
        let slot = handle
            .path()
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or(ReconcileError::Spool)?;
        descriptors.push(ReconciliationArtifactDescriptor {
            kind: ReconciliationArtifactKind::GapMarker,
            artifact_id: format!("gap-marker:{slot}"),
            marker_id: Some(marker.marker_id.clone()),
            redacted_fingerprint: Some(marker.redacted_fingerprint.clone()),
            session_ref: Some(marker.session_ref.clone()),
            source_ref: Some(marker.source_ref.clone()),
        });
    }
    for handle in quarantines {
        let marker_id = quarantine_marker_id(handle);
        descriptors.push(ReconciliationArtifactDescriptor {
            kind: ReconciliationArtifactKind::Quarantine,
            artifact_id: marker_id.clone(),
            marker_id: Some(marker_id),
            redacted_fingerprint: Some(handle.fingerprint().to_owned()),
            session_ref: None,
            source_ref: None,
        });
    }
    Ok(descriptors)
}

fn quarantine_marker_id(handle: &PendingQuarantine) -> String {
    format!(
        "quarantine:{}:{}:{}",
        handle.device(),
        handle.inode(),
        handle.length()
    )
}

fn validate_reconcile_input(input: &ReconcileInput) -> Result<(), ReconcileError> {
    input
        .runtime_snapshot
        .validate()
        .map_err(|_| ReconcileError::InvalidInput)?;
    if input.max_items == 0
        || input.max_items > MAX_RECONCILE_ITEMS
        || input.algorithm_revision.is_empty()
        || input.algorithm_revision.len() > 256
        || input.occurred_at_us < 0
        || input.liveness.iter().any(|value| {
            value.host_session_id.is_empty()
                || value.agent_id.is_empty()
                || value.host_lane_key.is_empty()
                || value.incarnation_ref.is_empty()
                || value.evidence_ref.is_empty()
        })
        || input
            .independent_source_reconciliations
            .iter()
            .any(|value| {
                value.host_session_id.is_empty()
                    || value.agent_id.is_empty()
                    || value.host_lane_key.is_empty()
                    || value.incarnation_ref.is_empty()
                    || value.first_sequence > value.last_sequence
                    || value.evidence_refs.is_empty()
                    || value.evidence_refs.iter().any(String::is_empty)
            })
    {
        return Err(ReconcileError::InvalidInput);
    }
    for manifest in &input.adapter_manifests {
        compile_capture_contract(manifest, []).map_err(|_| ReconcileError::Manifest)?;
    }
    Ok(())
}

fn import_emergency_markers(
    handles: &[PendingGapMarker],
    state: &mut CurrentCaptureState,
    input: &ReconcileInput,
    payloads: &mut Vec<JournalPayload>,
    pending_ids: &mut Vec<String>,
    progress: &mut ReconcileProgress,
    remaining: &mut usize,
) -> Result<(), ReconcileError> {
    for handle in handles {
        let marker = handle.marker();
        if let Some(existing) = state.capture_gaps.get(&marker.marker_id) {
            if !gap_matches_marker(existing, marker) {
                return Err(ReconcileError::Projection);
            }
            pending_ids.push(marker.marker_id.clone());
            continue;
        }
        if *remaining == 0 {
            continue;
        }
        *remaining -= 1;
        pending_ids.push(marker.marker_id.clone());
        let evidence = CaptureGapMarkerEvidence {
            marker_id: marker.marker_id.clone(),
            reconciliation_revision: 1,
            predecessor_revision: None,
            source_ref: marker.source_ref.clone(),
            session_ref: marker.session_ref.clone(),
            turn_ref: marker.turn_ref.clone(),
            tool_ref: marker.tool_ref.clone(),
            failure_reason: format!("{:?}", marker.failure_reason).to_ascii_lowercase(),
            redacted_fingerprint: marker.redacted_fingerprint.clone(),
            attempted_bytes: marker.attempted_bytes,
            last_durable_watermark: marker.last_durable_watermark,
            provenance: ReconciliationProvenance::EmergencyMarker,
            import_ref: handle.path().display().to_string(),
            reconciled: false,
            reconciliation_refs: Vec::new(),
        };
        evidence.validate().map_err(|_| ReconcileError::Domain)?;
        payloads.push(JournalPayload::CaptureGapMarkerRecorded(Box::new(
            evidence.clone(),
        )));
        state
            .capture_gaps
            .insert(evidence.marker_id.clone(), evidence);
        progress.gap_revisions_recorded += 1;
        if payloads.len() > input.max_items.saturating_mul(8) {
            return Err(ReconcileError::InvalidInput);
        }
    }
    Ok(())
}

fn import_quarantine(
    handles: &[PendingQuarantine],
    state: &mut CurrentCaptureState,
    input: &ReconcileInput,
    payloads: &mut Vec<JournalPayload>,
    pending_ids: &mut Vec<String>,
    progress: &mut ReconcileProgress,
    remaining: &mut usize,
) -> Result<(), ReconcileError> {
    for handle in handles {
        let marker_id = quarantine_marker_id(handle);
        if let Some(existing) = state.capture_gaps.get(&marker_id) {
            if existing.redacted_fingerprint != handle.fingerprint()
                || existing.provenance != ReconciliationProvenance::QuarantineRecovery
                || existing.attempted_bytes != handle.length()
            {
                return Err(ReconcileError::Projection);
            }
            pending_ids.push(marker_id);
            continue;
        }
        if *remaining == 0 {
            continue;
        }
        *remaining -= 1;
        pending_ids.push(marker_id.clone());
        let evidence = CaptureGapMarkerEvidence {
            marker_id: marker_id.clone(),
            reconciliation_revision: 1,
            predecessor_revision: None,
            source_ref: "durable-spool".into(),
            session_ref: "unresolved-quarantine".into(),
            turn_ref: None,
            tool_ref: None,
            failure_reason: "corrupt-sealed-segment".into(),
            redacted_fingerprint: handle.fingerprint().to_owned(),
            attempted_bytes: handle.length(),
            last_durable_watermark: 0,
            provenance: ReconciliationProvenance::QuarantineRecovery,
            import_ref: handle.path().display().to_string(),
            reconciled: false,
            reconciliation_refs: Vec::new(),
        };
        evidence.validate().map_err(|_| ReconcileError::Domain)?;
        payloads.push(JournalPayload::CaptureGapMarkerRecorded(Box::new(
            evidence.clone(),
        )));
        state.capture_gaps.insert(marker_id, evidence);
        progress.gap_revisions_recorded += 1;
        if payloads.len() > input.max_items.saturating_mul(8) {
            return Err(ReconcileError::InvalidInput);
        }
    }
    Ok(())
}

fn gap_matches_marker(
    evidence: &CaptureGapMarkerEvidence,
    marker: &evertrace_capture::CaptureGapMarker,
) -> bool {
    evidence.source_ref == marker.source_ref
        && evidence.session_ref == marker.session_ref
        && evidence.turn_ref == marker.turn_ref
        && evidence.tool_ref == marker.tool_ref
        && evidence.failure_reason == format!("{:?}", marker.failure_reason).to_ascii_lowercase()
        && evidence.redacted_fingerprint == marker.redacted_fingerprint
        && evidence.attempted_bytes == marker.attempted_bytes
        && evidence.last_durable_watermark == marker.last_durable_watermark
        && evidence.provenance == ReconciliationProvenance::EmergencyMarker
}

fn apply_reconciled_evidence(
    input: &ReconcileInput,
    state: &mut CurrentCaptureState,
    payloads: &mut Vec<JournalPayload>,
    progress: &mut ReconcileProgress,
    remaining: &mut usize,
) -> Result<BTreeSet<LaneIdentityKey>, ReconcileError> {
    let mut targets = BTreeSet::new();
    let mut gaps = input.reconciled_gaps.iter().collect::<Vec<_>>();
    gaps.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    for resolved in gaps {
        if *remaining == 0 {
            break;
        }
        *remaining -= 1;
        let Some(current) = state.capture_gaps.get(&resolved.evidence_id).cloned() else {
            return Err(ReconcileError::InvalidInput);
        };
        targets.extend(identities_for_gap(state, &current));
        if current.reconciled {
            continue;
        }
        let mut successor = current;
        successor.reconciliation_revision += 1;
        successor.predecessor_revision = Some(successor.reconciliation_revision - 1);
        successor.reconciled = true;
        successor.reconciliation_refs = resolved.reconciliation_refs.clone();
        successor.validate().map_err(|_| ReconcileError::Domain)?;
        payloads.push(JournalPayload::CaptureGapMarkerRecorded(Box::new(
            successor.clone(),
        )));
        state
            .capture_gaps
            .insert(resolved.evidence_id.clone(), successor);
        progress.gap_revisions_recorded += 1;
    }
    let mut outages = input.reconciled_outages.iter().collect::<Vec<_>>();
    outages.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    for resolved in outages {
        if *remaining == 0 {
            break;
        }
        *remaining -= 1;
        let id = CaptureOutageIntervalId::from_str(&resolved.evidence_id)
            .map_err(|_| ReconcileError::InvalidInput)?;
        let Some(current) = state.capture_outages.get(&id).cloned() else {
            return Err(ReconcileError::InvalidInput);
        };
        targets.extend(identities_for_outage(state, &current));
        if current.reconciled {
            continue;
        }
        let mut successor = current;
        successor.reconciliation_revision += 1;
        successor.predecessor_revision = Some(successor.reconciliation_revision - 1);
        successor.reconciled = true;
        successor.reconciliation_refs = resolved.reconciliation_refs.clone();
        successor.validate().map_err(|_| ReconcileError::Domain)?;
        payloads.push(JournalPayload::CaptureOutageIntervalRecorded(Box::new(
            successor.clone(),
        )));
        state.capture_outages.insert(id, successor);
        progress.outage_revisions_recorded += 1;
    }
    Ok(targets)
}

fn normalize_selected_dirty(
    selected: &[DirtyRow],
    state: &mut CurrentCaptureState,
    payloads: &mut Vec<JournalPayload>,
    progress: &mut ReconcileProgress,
) -> Result<(), ReconcileError> {
    let physical = selected
        .iter()
        .filter(|dirty| dirty.target_kind == DirtyTargetKind::PhysicalNormalization)
        .collect::<Vec<_>>();
    if physical.is_empty() {
        return Ok(());
    }
    let normalization_state = CurrentCaptureState::from_dependencies(
        physical
            .iter()
            .flat_map(|dirty| dirty.dependencies.iter().cloned()),
    )?;
    let selected_ids = physical
        .iter()
        .map(|dirty| SourceObservationId::from_str(&dirty.target_id))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| ReconcileError::Projection)?;
    let previous = crate::NormalizationSnapshot {
        occurrences: normalization_state.host_occurrences.clone(),
        operations: normalization_state.operations.clone(),
        scope_effects: normalization_state.scope_effects.clone(),
    };
    let normalized = crate::PhysicalNormalizer::new(1)
        .map_err(|_| ReconcileError::Domain)?
        .normalize(
            &normalization_state
                .source_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            (!previous.occurrences.is_empty()).then_some(&previous),
        )
        .map_err(|_| ReconcileError::Domain)?;
    for occurrence in &normalized.occurrences {
        let changed = normalization_state
            .host_occurrences
            .iter()
            .find(|current| current.host_occurrence_id == occurrence.host_occurrence_id)
            != Some(occurrence);
        if changed {
            payloads.push(JournalPayload::HostOccurrenceNormalized(Box::new(
                occurrence.clone(),
            )));
            progress.physical_normalization_recorded += 1;
        }
    }
    for operation in &normalized.operations {
        let changed = normalization_state
            .operations
            .iter()
            .find(|current| current.operation_id == operation.operation_id)
            != Some(operation);
        if changed {
            payloads.push(JournalPayload::OperationDerived(Box::new(
                operation.clone(),
            )));
            progress.physical_normalization_recorded += 1;
        }
    }
    for effect in &normalized.scope_effects {
        if !normalization_state
            .scope_effects
            .iter()
            .any(|current| current == effect)
        {
            payloads.push(JournalPayload::ScopeEffectDerived(Box::new(effect.clone())));
            progress.physical_normalization_recorded += 1;
        }
    }
    for id in selected_ids {
        payloads.push(JournalPayload::NormalizationWatermark(
            NormalizationWatermark {
                source_observation_id: id,
                resolver_version: 1,
            },
        ));
        state.normalization_watermarks.insert(id);
    }
    for occurrence in normalized.occurrences {
        state
            .host_occurrences
            .retain(|current| current.host_occurrence_id != occurrence.host_occurrence_id);
        state.host_occurrences.push(occurrence);
    }
    for operation in normalized.operations {
        state
            .operations
            .retain(|current| current.operation_id != operation.operation_id);
        state.operations.push(operation);
    }
    for effect in normalized.scope_effects {
        state
            .scope_effects
            .retain(|current| current.scope_effect_id != effect.scope_effect_id);
        state.scope_effects.push(effect);
    }
    Ok(())
}

fn lane_groups(
    receipts: &[SourceReceipt],
) -> Result<BTreeMap<LaneIncarnationKey, Vec<SourceReceipt>>, ReconcileError> {
    let mut groups = BTreeMap::<LaneIncarnationKey, Vec<SourceReceipt>>::new();
    for receipt in receipts {
        if let Some(lifecycle) = &receipt.lifecycle {
            groups
                .entry(LaneIncarnationKey {
                    identity: LaneIdentityKey::from_lifecycle(lifecycle),
                    incarnation_ref: lifecycle_incarnation_ref(
                        lifecycle,
                        receipt.source_observation_id,
                    ),
                })
                .or_default()
                .push(receipt.clone());
        }
    }
    for values in groups.values_mut() {
        values.sort_by(|left, right| {
            let left_lifecycle = left.lifecycle.as_ref().expect("filtered lifecycle");
            let right_lifecycle = right.lifecycle.as_ref().expect("filtered lifecycle");
            left_lifecycle
                .lane_sequence
                .cmp(&right_lifecycle.lane_sequence)
                .then_with(|| left.recorded_at_us.cmp(&right.recorded_at_us))
                .then_with(|| {
                    left.source_observation_id
                        .to_string()
                        .cmp(&right.source_observation_id.to_string())
                })
        });
    }
    Ok(groups)
}

fn lifecycle_incarnation_ref(
    lifecycle: &evertrace_domain::work::LaneLifecycleEvidence,
    source_observation_id: SourceObservationId,
) -> String {
    lifecycle
        .incarnation_ref
        .clone()
        .unwrap_or_else(|| format!("source-observation:{source_observation_id}"))
}

fn lane_ids_for_groups(
    groups: &BTreeMap<LaneIncarnationKey, Vec<SourceReceipt>>,
    state: &CurrentCaptureState,
) -> Result<BTreeMap<LaneIncarnationKey, ExecutionLaneId>, ReconcileError> {
    let mut existing = BTreeMap::new();
    for lane in state.execution_lanes.values() {
        let key = LaneIncarnationKey {
            identity: LaneIdentityKey::from_lane(lane),
            incarnation_ref: lane.incarnation_ref.clone(),
        };
        if existing.insert(key, lane.execution_lane_id).is_some() {
            return Err(ReconcileError::Projection);
        }
    }
    Ok(groups
        .keys()
        .map(|key| {
            (
                key.clone(),
                existing
                    .get(key)
                    .copied()
                    .unwrap_or_else(ExecutionLaneId::new_v7),
            )
        })
        .collect())
}

fn observed_capabilities(receipts: &[&SourceReceipt]) -> Vec<ObservableCapability> {
    let mut values = BTreeSet::new();
    let child_ids = receipts
        .iter()
        .filter_map(|receipt| receipt.lifecycle.as_ref())
        .filter_map(|lifecycle| lifecycle.child_session_id.clone())
        .collect::<BTreeSet<_>>();
    if child_ids.len() == 1 {
        values.insert(ObservableCapability::ChildSessionId);
    }
    for receipt in receipts {
        if let Some(lifecycle) = &receipt.lifecycle {
            if lifecycle.spawn_event_ref.is_some() {
                values.insert(ObservableCapability::DelegationStart);
            }
            if lifecycle.terminal_event_ref.is_some() {
                values.insert(ObservableCapability::DelegationEnd);
            }
            if lifecycle.host_final_return {
                values.insert(ObservableCapability::ChildFinalResult);
            }
        }
        match receipt.observation_role {
            ObservationRole::Intent => {
                values.insert(ObservableCapability::ChildToolCall);
            }
            ObservationRole::Result => {
                values.insert(ObservableCapability::ChildToolResult);
            }
            ObservationRole::Lifecycle
            | ObservationRole::Message
            | ObservationRole::StateProbe
            | ObservationRole::Artifact
            | ObservationRole::Other => {}
        }
    }
    values.into_iter().collect()
}

fn identities_for_gap(
    state: &CurrentCaptureState,
    gap: &CaptureGapMarkerEvidence,
) -> BTreeSet<LaneIdentityKey> {
    state
        .source_receipts
        .iter()
        .filter(|receipt| gap_affects_receipt(gap, receipt))
        .filter_map(|receipt| receipt.lifecycle.as_ref())
        .map(LaneIdentityKey::from_lifecycle)
        .collect()
}

fn identities_for_outage(
    state: &CurrentCaptureState,
    outage: &CaptureOutageInterval,
) -> BTreeSet<LaneIdentityKey> {
    state
        .source_receipts
        .iter()
        .filter(|receipt| {
            receipt.source_session_ref == outage.session_ref
                && source_revision_ref_for(receipt) == outage.source_ref
        })
        .filter_map(|receipt| receipt.lifecycle.as_ref())
        .map(LaneIdentityKey::from_lifecycle)
        .collect()
}

fn gap_affects_receipt(gap: &CaptureGapMarkerEvidence, receipt: &SourceReceipt) -> bool {
    gap.session_ref == receipt.source_session_ref
        && (gap.source_ref == receipt.source_ref
            || gap.source_ref == source_revision_ref_for(receipt))
}

fn source_revision_ref_for(receipt: &SourceReceipt) -> String {
    format!(
        "{}@{}",
        receipt.source_instance_id.as_str(),
        receipt.source_revision.as_str()
    )
}

fn group_for_observation(
    groups: &BTreeMap<LaneIncarnationKey, Vec<SourceReceipt>>,
    observation_id: SourceObservationId,
) -> Option<&LaneIncarnationKey> {
    groups.iter().find_map(|(key, receipts)| {
        receipts
            .iter()
            .any(|receipt| receipt.source_observation_id == observation_id)
            .then_some(key)
    })
}

fn dirty_rows(frontier: &ReconciliationFrontier, limit: usize) -> Vec<DirtyRow> {
    frontier
        .items
        .iter()
        .take(limit)
        .map(|item| DirtyRow {
            source_event_seq: item.source_event_seq,
            target_kind: item.target_kind,
            target_id: item.target_id.clone(),
            dependencies: item.dependencies.clone(),
        })
        .collect()
}

#[derive(Clone)]
struct ManifestEvaluation<'a> {
    manifests: Vec<&'a AdapterCapabilityManifest>,
    coverage: Vec<CoverageLevel>,
    required: BTreeSet<String>,
    observed: BTreeSet<String>,
    child_session_id: Option<String>,
}

fn evaluate_manifests<'a>(
    receipts: &[&SourceReceipt],
    manifests: &'a BTreeMap<String, &'a AdapterCapabilityManifest>,
) -> Result<ManifestEvaluation<'a>, ReconcileError> {
    let ids = receipts
        .iter()
        .map(|receipt| receipt.adapter_manifest_ref.as_str())
        .collect::<BTreeSet<_>>();
    let child_ids = receipts
        .iter()
        .filter_map(|receipt| receipt.lifecycle.as_ref())
        .filter_map(|lifecycle| lifecycle.child_session_id.clone())
        .collect::<BTreeSet<_>>();
    let child_session_id = (child_ids.len() == 1)
        .then(|| child_ids.iter().next().cloned())
        .flatten();
    let mut values = Vec::new();
    let mut coverage = Vec::new();
    let mut required = BTreeSet::new();
    let mut observed = BTreeSet::new();
    for id in ids {
        let manifest = manifests.get(id).copied().ok_or(ReconcileError::Manifest)?;
        let manifest_receipts = receipts
            .iter()
            .copied()
            .filter(|receipt| receipt.adapter_manifest_ref == id)
            .collect::<Vec<_>>();
        let contract =
            compile_capture_contract(manifest, observed_capabilities(&manifest_receipts))
                .map_err(|_| ReconcileError::Manifest)?;
        required.extend(contract.required_for_full);
        observed.extend(contract.observed);
        coverage.push(match manifest.capture_guarantee {
            CaptureGuarantee::Opaque => CoverageLevel::Opaque,
            CaptureGuarantee::Partial => CoverageLevel::Partial,
            CaptureGuarantee::Full if !contract.missing_required.is_empty() => {
                CoverageLevel::Partial
            }
            CaptureGuarantee::Full => CoverageLevel::Full,
        });
        values.push(manifest);
    }
    Ok(ManifestEvaluation {
        manifests: values,
        coverage,
        required,
        observed,
        child_session_id,
    })
}

fn effective_lifecycle(
    key: &LaneIncarnationKey,
    receipts: &[&SourceReceipt],
) -> Result<evertrace_domain::work::LaneLifecycleEvidence, ReconcileError> {
    let mut lifecycles = receipts
        .iter()
        .filter_map(|receipt| receipt.lifecycle.as_ref())
        .collect::<Vec<_>>();
    lifecycles.sort_by_key(|lifecycle| lifecycle.lane_sequence);
    let mut effective = lifecycles
        .last()
        .cloned()
        .cloned()
        .ok_or(ReconcileError::Domain)?;
    effective.incarnation_ref = Some(key.incarnation_ref.clone());
    let spawn_refs = lifecycles
        .iter()
        .filter_map(|lifecycle| lifecycle.spawn_event_ref.clone())
        .collect::<BTreeSet<_>>();
    if spawn_refs.len() > 1 {
        return Err(ReconcileError::Domain);
    }
    effective.spawn_event_ref = spawn_refs.into_iter().next();
    let terminals = lifecycles
        .iter()
        .filter(|lifecycle| lifecycle.terminal_kind.is_some())
        .map(|lifecycle| {
            (
                lifecycle.terminal_kind,
                lifecycle.terminal_event_ref.clone(),
                lifecycle.host_final_return,
            )
        })
        .collect::<Vec<_>>();
    if terminals
        .iter()
        .skip(1)
        .any(|terminal| terminal != &terminals[0])
    {
        return Err(ReconcileError::Domain);
    }
    if let Some((kind, event_ref, host_final_return)) = terminals.into_iter().next() {
        effective.terminal_kind = kind;
        effective.terminal_event_ref = event_ref;
        effective.host_final_return = host_final_return;
    } else {
        effective.terminal_kind = None;
        effective.terminal_event_ref = None;
        effective.host_final_return = false;
    }
    let parent_keys = lifecycles
        .iter()
        .filter_map(|lifecycle| lifecycle.parent_host_lane_key.clone())
        .collect::<BTreeSet<_>>();
    if parent_keys.len() > 1 {
        return Err(ReconcileError::Domain);
    }
    effective.parent_host_lane_key = parent_keys.into_iter().next();
    effective.validate().map_err(|_| ReconcileError::Domain)?;
    Ok(effective)
}

#[derive(Clone)]
struct SourceSummary {
    source_instance_id: SourceInstanceId,
    source_revision: SourceRevision,
    source_ref: String,
    sequences: BTreeSet<u64>,
    sequence_origin: Option<u64>,
    close_watermark: Option<u64>,
    eligible_event_manifest_refs: BTreeSet<String>,
    close_refs: BTreeSet<String>,
    admission_failure_observability: AdmissionFailureObservability,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MissingInterval {
    first: u64,
    last: u64,
}

fn missing_intervals(
    sequences: &BTreeSet<u64>,
    close: Option<u64>,
    sequence_origin: Option<u64>,
) -> Vec<MissingInterval> {
    let Some(first_observed) = sequences.first().copied() else {
        return Vec::new();
    };
    let start = sequence_origin.unwrap_or(first_observed);
    let end = close.unwrap_or_else(|| sequences.last().copied().unwrap_or(start));
    let mut missing = Vec::new();
    let mut expected = start;
    for sequence in sequences
        .iter()
        .copied()
        .filter(|sequence| *sequence <= end)
    {
        if sequence > expected {
            missing.push(MissingInterval {
                first: expected,
                last: sequence - 1,
            });
        }
        expected = sequence.saturating_add(1);
    }
    if expected <= end {
        missing.push(MissingInterval {
            first: expected,
            last: end,
        });
    }
    missing
}

fn source_summaries(
    lane_receipts: &[&SourceReceipt],
    all_receipts: &[SourceReceipt],
    manifests: &BTreeMap<String, &AdapterCapabilityManifest>,
) -> Result<Vec<SourceSummary>, ReconcileError> {
    let relevant_sources = lane_receipts
        .iter()
        .map(|receipt| source_revision_ref_for(receipt))
        .collect::<BTreeSet<_>>();
    let mut grouped = BTreeMap::<String, Vec<&SourceReceipt>>::new();
    for receipt in all_receipts {
        let source_ref = source_revision_ref_for(receipt);
        if relevant_sources.contains(&source_ref) {
            grouped.entry(source_ref).or_default().push(receipt);
        }
    }
    let mut summaries = Vec::new();
    for (source_ref, values) in grouped {
        let close_values = values
            .iter()
            .filter_map(|receipt| receipt.close_watermark)
            .collect::<BTreeSet<_>>();
        if close_values.len() > 1 {
            return Err(ReconcileError::Domain);
        }
        let source_manifests = values
            .iter()
            .map(|receipt| receipt.adapter_manifest_ref.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|id| manifests.get(id).copied().ok_or(ReconcileError::Manifest))
            .collect::<Result<Vec<_>, _>>()?;
        let first = values.first().ok_or(ReconcileError::Domain)?;
        let sequences = values
            .iter()
            .map(|receipt| receipt.source_sequence)
            .collect::<BTreeSet<_>>();
        let origins = values
            .iter()
            .filter_map(|receipt| receipt.source_sequence_origin)
            .collect::<BTreeSet<_>>();
        if origins.len() > 1
            || origins
                .first()
                .is_some_and(|origin| sequences.first().is_some_and(|first| origin > first))
        {
            return Err(ReconcileError::Domain);
        }
        summaries.push(SourceSummary {
            source_instance_id: first.source_instance_id.clone(),
            source_revision: first.source_revision.clone(),
            source_ref,
            sequences,
            sequence_origin: origins.into_iter().next(),
            close_watermark: close_values.into_iter().next(),
            eligible_event_manifest_refs: values
                .iter()
                .map(|receipt| receipt.eligible_event_manifest_ref.clone())
                .collect(),
            close_refs: values
                .iter()
                .filter(|receipt| receipt.close_watermark.is_some())
                .map(|receipt| receipt.source_receipt_id.to_string())
                .chain(values.iter().filter_map(|receipt| {
                    receipt
                        .lifecycle
                        .as_ref()
                        .and_then(|lifecycle| lifecycle.source_close_ref.clone())
                }))
                .collect(),
            admission_failure_observability: weakest_observability(&source_manifests),
        });
    }
    Ok(summaries)
}

fn ensure_source_outages(
    lifecycle: &evertrace_domain::work::LaneLifecycleEvidence,
    summaries: &[SourceSummary],
    previous: Option<&CaptureReceipt>,
    state: &mut CurrentCaptureState,
    payloads: &mut Vec<JournalPayload>,
    progress: &mut ReconcileProgress,
) -> Result<(Vec<CaptureOutageIntervalId>, Vec<CaptureOutageIntervalId>), ReconcileError> {
    let mut current_missing = BTreeSet::new();
    for source in summaries {
        for interval in missing_intervals(
            &source.sequences,
            source.close_watermark,
            source.sequence_origin,
        ) {
            current_missing.insert((source.source_ref.clone(), interval));
            let existing = state
                .capture_outages
                .values()
                .find(|outage| {
                    outage.session_ref == lifecycle.host_session_id
                        && outage.source_ref == source.source_ref
                        && outage.first_missing_sequence == interval.first
                        && outage.last_missing_sequence == interval.last
                })
                .map(|outage| outage.capture_outage_interval_id);
            if existing.is_none() {
                let id = CaptureOutageIntervalId::new_v7();
                let outage = CaptureOutageInterval {
                    capture_outage_interval_id: id,
                    reconciliation_revision: 1,
                    predecessor_revision: None,
                    source_ref: source.source_ref.clone(),
                    session_ref: lifecycle.host_session_id.clone(),
                    first_missing_sequence: interval.first,
                    last_missing_sequence: interval.last,
                    positive_source: CaptureOutagePositiveSource::MonotonicSequenceGap,
                    positive_evidence_refs: vec![format!(
                        "source-gap:{}:{}-{}",
                        source.source_ref, interval.first, interval.last
                    )],
                    reconciled: false,
                    reconciliation_refs: Vec::new(),
                };
                outage.validate().map_err(|_| ReconcileError::Domain)?;
                payloads.push(JournalPayload::CaptureOutageIntervalRecorded(Box::new(
                    outage.clone(),
                )));
                state.capture_outages.insert(id, outage);
                progress.outage_revisions_recorded += 1;
            }
        }
    }
    let source_refs = summaries
        .iter()
        .map(|summary| summary.source_ref.as_str())
        .collect::<BTreeSet<_>>();
    let stale = state
        .capture_outages
        .iter()
        .filter(|(_, outage)| {
            outage.session_ref == lifecycle.host_session_id
                && source_refs.contains(outage.source_ref.as_str())
                && !outage.reconciled
                && !current_missing.contains(&(
                    outage.source_ref.clone(),
                    MissingInterval {
                        first: outage.first_missing_sequence,
                        last: outage.last_missing_sequence,
                    },
                ))
        })
        .map(|(id, outage)| (*id, outage.clone()))
        .collect::<Vec<_>>();
    for (id, mut successor) in stale {
        successor.reconciliation_revision += 1;
        successor.predecessor_revision = Some(successor.reconciliation_revision - 1);
        successor.reconciled = true;
        successor.reconciliation_refs = vec![format!(
            "late-source-evidence:{}:{}-{}",
            successor.source_ref, successor.first_missing_sequence, successor.last_missing_sequence
        )];
        successor.validate().map_err(|_| ReconcileError::Domain)?;
        payloads.push(JournalPayload::CaptureOutageIntervalRecorded(Box::new(
            successor.clone(),
        )));
        state.capture_outages.insert(id, successor);
        progress.outage_revisions_recorded += 1;
    }
    let mut historical = previous
        .map(|receipt| receipt.capture_outage_interval_refs.clone())
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();
    historical.extend(state.capture_outages.iter().filter_map(|(id, outage)| {
        (outage.session_ref == lifecycle.host_session_id
            && source_refs.contains(outage.source_ref.as_str()))
        .then_some(*id)
    }));
    let unresolved = historical
        .iter()
        .copied()
        .filter(|id| {
            state
                .capture_outages
                .get(id)
                .is_some_and(|outage| !outage.reconciled)
        })
        .collect();
    Ok((historical.into_iter().collect(), unresolved))
}

fn contiguous_through(source: &SourceSummary) -> u64 {
    let Some(first_observed) = source.sequences.first().copied() else {
        return 0;
    };
    let mut expected = source.sequence_origin.unwrap_or(first_observed);
    for sequence in &source.sequences {
        if *sequence < expected {
            continue;
        }
        if *sequence != expected {
            break;
        }
        expected = expected.saturating_add(1);
    }
    expected.saturating_sub(1)
}

struct CloseReconciliationInput<'a> {
    lane_id: ExecutionLaneId,
    next_lane_revision: u32,
    import_frontier: u64,
    summaries: &'a [SourceSummary],
    unresolved_gaps: &'a [String],
    unresolved_outages: &'a [CaptureOutageIntervalId],
    independent: Option<&'a IndependentSourceReconciliation>,
}

fn close_reconciliation(
    input: CloseReconciliationInput<'_>,
    state: &mut CurrentCaptureState,
    payloads: &mut Vec<JournalPayload>,
) -> Result<Option<SourceCloseReconciliation>, ReconcileError> {
    let CloseReconciliationInput {
        lane_id,
        next_lane_revision,
        import_frontier,
        summaries,
        unresolved_gaps,
        unresolved_outages,
        independent,
    } = input;
    if summaries.is_empty()
        || summaries
            .iter()
            .any(|source| source.close_watermark.is_none())
    {
        return Ok(None);
    }
    let mut ranges = Vec::new();
    for source in summaries {
        let first_sequence = source.sequence_origin.unwrap_or(
            source
                .sequences
                .first()
                .copied()
                .ok_or(ReconcileError::Domain)?,
        );
        let independent_reconciliation = independent
            .filter(|proof| {
                proof.source_instance_id != source.source_instance_id
                    || proof.source_revision != source.source_revision
            })
            .map(|proof| StoreIndependentSourceReconciliation {
                source_instance_id: proof.source_instance_id.clone(),
                source_revision: proof.source_revision.clone(),
                first_sequence: proof.first_sequence,
                last_sequence: proof.last_sequence,
                evidence_refs: proof.evidence_refs.clone(),
            });
        ranges.push(SourceCloseRange {
            source_instance_id: source.source_instance_id.clone(),
            source_revision: source.source_revision.clone(),
            eligible_event_manifest_refs: source
                .eligible_event_manifest_refs
                .iter()
                .cloned()
                .collect(),
            first_sequence,
            close_watermark: source.close_watermark.ok_or(ReconcileError::Domain)?,
            observed_through_sequence: contiguous_through(source),
            admission_failure_observability: source.admission_failure_observability,
            independent_reconciliation,
        });
    }
    if let Some(existing) = state
        .source_close_reconciliations
        .values()
        .find(|existing| {
            existing.execution_lane_id == lane_id
                && existing.sources == ranges
                && existing.unresolved_gap_refs == unresolved_gaps
                && existing.unresolved_outage_interval_refs == unresolved_outages
        })
    {
        return Ok(Some(existing.clone()));
    }
    let reconciliation_ref = format!("close:{lane_id}:{next_lane_revision}:{import_frontier}");
    let proof = SourceCloseReconciliation::new(
        reconciliation_ref.clone(),
        lane_id,
        ranges,
        unresolved_gaps.to_vec(),
        unresolved_outages.to_vec(),
    )
    .map_err(|_| ReconcileError::Domain)?;
    if let Some(existing) = state.source_close_reconciliations.get(&reconciliation_ref) {
        if existing != &proof {
            return Err(ReconcileError::Projection);
        }
        return Ok(Some(existing.clone()));
    }
    payloads.push(JournalPayload::SourceCloseReconciliation(proof.clone()));
    state
        .source_close_reconciliations
        .insert(reconciliation_ref, proof.clone());
    Ok(Some(proof))
}

fn pairing_for_group(
    state: &CurrentCaptureState,
    groups: &BTreeMap<LaneIncarnationKey, Vec<SourceReceipt>>,
    key: &LaneIncarnationKey,
    eligible_observation_ids: &BTreeSet<SourceObservationId>,
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let observation_group = groups
        .iter()
        .flat_map(|(group, receipts)| {
            receipts
                .iter()
                .map(move |receipt| (receipt.source_observation_id, group))
        })
        .collect::<BTreeMap<_, _>>();
    let operations = state.operations.iter().filter(|operation| {
        operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .any(|id| observation_group.get(id).is_some_and(|group| *group == key))
    });
    let mut calls = Vec::new();
    let mut results = Vec::new();
    let mut unmatched_calls = Vec::new();
    let mut unmatched_results = Vec::new();
    for operation in operations {
        let id = operation.operation_id.to_string();
        let input_seen = operation
            .input_source_observation_refs
            .iter()
            .any(|observation| eligible_observation_ids.contains(observation));
        let result_seen = operation
            .result_source_observation_refs
            .iter()
            .any(|observation| eligible_observation_ids.contains(observation));
        if input_seen {
            calls.push(id.clone());
        }
        if result_seen {
            results.push(id.clone());
        }
        if input_seen && !result_seen {
            unmatched_calls.push(id);
        } else if result_seen && !input_seen {
            unmatched_results.push(id);
        }
    }
    (calls, results, unmatched_calls, unmatched_results)
}

fn operation_lane_successors_typed(
    state: &CurrentCaptureState,
    groups: &BTreeMap<LaneIncarnationKey, Vec<SourceReceipt>>,
    lane_ids: &BTreeMap<LaneIncarnationKey, ExecutionLaneId>,
    targets: &BTreeSet<LaneIncarnationKey>,
    payloads: &mut Vec<JournalPayload>,
    progress: &mut ReconcileProgress,
) -> Result<BTreeMap<LaneIncarnationKey, Vec<evertrace_domain::ids::OperationId>>, ReconcileError> {
    let observation_group = groups
        .iter()
        .flat_map(|(group, receipts)| {
            receipts
                .iter()
                .map(move |receipt| (receipt.source_observation_id, group.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut result = BTreeMap::new();
    for operation in &state.operations {
        let keys = operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .filter_map(|id| observation_group.get(id).cloned())
            .collect::<BTreeSet<_>>();
        if keys.len() != 1 {
            continue;
        }
        let key = keys.into_iter().next().ok_or(ReconcileError::Domain)?;
        if !targets.contains(&key) {
            continue;
        }
        let lane_id = lane_ids.get(&key).copied().ok_or(ReconcileError::Domain)?;
        if operation
            .execution_lane_id
            .is_some_and(|current| current != lane_id)
        {
            return Err(ReconcileError::Domain);
        }
        result
            .entry(key.clone())
            .or_insert_with(Vec::new)
            .push(operation.operation_id);
        if operation.execution_lane_id.is_none() {
            let mut successor = operation.clone();
            successor.execution_lane_id = Some(lane_id);
            let operation_is_pending = payloads.iter().any(|payload| {
                matches!(payload, JournalPayload::OperationDerived(value) if value.operation_id == operation.operation_id)
            });
            if !operation_is_pending {
                successor.previous_operation_revision = Some(operation.operation_revision);
                successor.operation_revision += 1;
            }
            successor.validate().map_err(|_| ReconcileError::Domain)?;
            if operation_is_pending {
                let pending = payloads
                    .iter_mut()
                    .find_map(|payload| match payload {
                        JournalPayload::OperationDerived(value)
                            if value.operation_id == operation.operation_id =>
                        {
                            Some(value)
                        }
                        _ => None,
                    })
                    .ok_or(ReconcileError::Domain)?;
                **pending = successor;
            } else {
                payloads.push(JournalPayload::OperationDerived(Box::new(successor)));
            }
            progress.operation_successors_recorded += 1;
        }
    }
    Ok(result)
}

struct LaneReconcileContext<'a> {
    input: &'a ReconcileInput,
    manifests: &'a BTreeMap<String, &'a AdapterCapabilityManifest>,
    groups: &'a BTreeMap<LaneIncarnationKey, Vec<SourceReceipt>>,
    lane_ids: &'a BTreeMap<LaneIncarnationKey, ExecutionLaneId>,
    selected_dirty: &'a [DirtyRow],
    explicit_targets: &'a BTreeSet<LaneIdentityKey>,
    pending_marker_ids: &'a [String],
    pending_quarantine_ids: &'a [String],
}

fn reconcile_lane_groups(
    context: LaneReconcileContext<'_>,
    state: &mut CurrentCaptureState,
    payloads: &mut Vec<JournalPayload>,
    progress: &mut ReconcileProgress,
    remaining: &mut usize,
) -> Result<(), ReconcileError> {
    let LaneReconcileContext {
        input,
        manifests,
        groups,
        lane_ids,
        selected_dirty,
        explicit_targets,
        pending_marker_ids,
        pending_quarantine_ids,
    } = context;
    let group_frontier = |key: &LaneIncarnationKey| {
        groups
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|receipt| {
                state
                    .source_receipt_event_seq
                    .get(&receipt.source_observation_id)
                    .copied()
            })
            .max()
            .unwrap_or(0)
    };
    let mut targets = BTreeMap::<LaneIncarnationKey, u64>::new();
    for dirty in selected_dirty {
        let observation_id = SourceObservationId::from_str(&dirty.target_id)
            .map_err(|_| ReconcileError::Projection)?;
        let key = group_for_observation(groups, observation_id)
            .ok_or(ReconcileError::Projection)?
            .clone();
        targets
            .entry(key)
            .and_modify(|frontier| *frontier = (*frontier).max(dirty.source_event_seq))
            .or_insert(dirty.source_event_seq);
    }
    for identity in explicit_targets {
        for key in groups.keys().filter(|key| &key.identity == identity) {
            targets
                .entry(key.clone())
                .or_insert_with(|| group_frontier(key));
        }
    }
    for marker_id in pending_marker_ids
        .iter()
        .chain(pending_quarantine_ids.iter())
    {
        if let Some(gap) = state.capture_gaps.get(marker_id) {
            let identities = identities_for_gap(state, gap);
            for identity in identities {
                for key in groups.keys().filter(|key| key.identity == identity) {
                    targets
                        .entry(key.clone())
                        .or_insert_with(|| group_frontier(key));
                }
            }
        }
    }
    let mut liveness_values = input.liveness.iter().collect::<Vec<_>>();
    liveness_values.sort_by(|left, right| {
        (
            &left.host_session_id,
            &left.agent_id,
            &left.host_lane_key,
            &left.incarnation_ref,
            &left.evidence_ref,
        )
            .cmp(&(
                &right.host_session_id,
                &right.agent_id,
                &right.host_lane_key,
                &right.incarnation_ref,
                &right.evidence_ref,
            ))
    });
    let mut liveness = BTreeMap::new();
    for value in liveness_values {
        if *remaining == 0 {
            break;
        }
        *remaining -= 1;
        let key = LaneIncarnationKey {
            identity: LaneIdentityKey {
                host_session_id: value.host_session_id.clone(),
                agent_id: value.agent_id.clone(),
                host_lane_key: value.host_lane_key.clone(),
            },
            incarnation_ref: value.incarnation_ref.clone(),
        };
        if liveness.insert(key.clone(), value).is_some() {
            return Err(ReconcileError::InvalidInput);
        }
        if groups.contains_key(&key) {
            targets
                .entry(key.clone())
                .or_insert_with(|| group_frontier(&key));
        }
    }
    let mut independent_values = input
        .independent_source_reconciliations
        .iter()
        .collect::<Vec<_>>();
    independent_values.sort_by(|left, right| {
        (
            &left.host_session_id,
            &left.agent_id,
            &left.host_lane_key,
            &left.incarnation_ref,
        )
            .cmp(&(
                &right.host_session_id,
                &right.agent_id,
                &right.host_lane_key,
                &right.incarnation_ref,
            ))
    });
    let mut independent = BTreeMap::new();
    for value in independent_values {
        if *remaining == 0 {
            break;
        }
        *remaining -= 1;
        let key = LaneIncarnationKey {
            identity: LaneIdentityKey {
                host_session_id: value.host_session_id.clone(),
                agent_id: value.agent_id.clone(),
                host_lane_key: value.host_lane_key.clone(),
            },
            incarnation_ref: value.incarnation_ref.clone(),
        };
        if independent.insert(key.clone(), value).is_some() {
            return Err(ReconcileError::InvalidInput);
        }
        if groups.contains_key(&key) {
            targets
                .entry(key.clone())
                .or_insert_with(|| group_frontier(&key));
        }
    }
    progress.lanes_considered = targets.len();
    let target_keys = targets.keys().cloned().collect::<BTreeSet<_>>();
    let operation_ids =
        operation_lane_successors_typed(state, groups, lane_ids, &target_keys, payloads, progress)?;
    for (key, import_frontier) in targets {
        let lane_id = *lane_ids.get(&key).ok_or(ReconcileError::Domain)?;
        let receipt_values = groups.get(&key).ok_or(ReconcileError::Domain)?;
        let receipts = receipt_values
            .iter()
            .filter(|receipt| {
                state
                    .source_receipt_event_seq
                    .get(&receipt.source_observation_id)
                    .is_some_and(|seq| *seq <= import_frontier)
            })
            .collect::<Vec<_>>();
        if receipts.is_empty() {
            continue;
        }
        let lifecycle = effective_lifecycle(&key, &receipts)?;
        let previous_lane = state.execution_lanes.get(&lane_id).cloned();
        let previous_receipt = state.capture_receipts.get(&lane_id).cloned();
        let import_frontier = previous_receipt
            .as_ref()
            .map_or(import_frontier, |receipt| {
                receipt.import_watermark.max(import_frontier)
            });
        let manifest = evaluate_manifests(&receipts, manifests)?;
        let available_source_receipts = state
            .source_receipts
            .iter()
            .filter(|receipt| {
                state
                    .source_receipt_event_seq
                    .get(&receipt.source_observation_id)
                    .is_some_and(|seq| *seq <= import_frontier)
            })
            .cloned()
            .collect::<Vec<_>>();
        let summaries = source_summaries(&receipts, &available_source_receipts, manifests)?;
        let relevant_gaps = state
            .capture_gaps
            .values()
            .filter(|gap| {
                receipts
                    .iter()
                    .any(|receipt| gap_affects_receipt(gap, receipt))
            })
            .collect::<Vec<_>>();
        let mut gap_refs = previous_receipt
            .as_ref()
            .map(|receipt| receipt.capture_gap_marker_refs.clone())
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        gap_refs.extend(relevant_gaps.iter().map(|gap| gap.marker_id.clone()));
        let unresolved_gap_refs = relevant_gaps
            .iter()
            .filter(|gap| !gap.reconciled)
            .map(|gap| gap.marker_id.clone())
            .collect::<Vec<_>>();
        let (outage_ids, unresolved_outages) = ensure_source_outages(
            &lifecycle,
            &summaries,
            previous_receipt.as_ref(),
            state,
            payloads,
            progress,
        )?;
        let independent_value = independent.get(&key).copied();
        let next_lane_revision = previous_lane
            .as_ref()
            .map_or(1, |lane| lane.lane_revision + 1);
        let proof = close_reconciliation(
            CloseReconciliationInput {
                lane_id,
                next_lane_revision,
                import_frontier,
                summaries: &summaries,
                unresolved_gaps: &unresolved_gap_refs,
                unresolved_outages: &unresolved_outages,
                independent: independent_value,
            },
            state,
            payloads,
        )?;
        let all_sources_closed = !summaries.is_empty()
            && summaries.iter().all(|source| {
                source.close_watermark.is_some_and(|watermark| {
                    source
                        .sequences
                        .last()
                        .is_some_and(|sequence| watermark >= *sequence)
                })
            });
        let source_reconciliation_complete = proof.as_ref().is_some_and(|proof| proof.passed());
        let mut reconciliation_refs = previous_receipt
            .as_ref()
            .map(|receipt| receipt.source_close_reconciliation_refs.clone())
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if let Some(proof) = &proof {
            reconciliation_refs.insert(proof.reconciliation_ref.clone());
        }
        let liveness_value = liveness.get(&key).copied();
        let liveness_state = liveness_value.map_or(lifecycle.liveness_state, |value| value.state);
        let liveness_refs = liveness_value
            .map(|value| vec![value.evidence_ref.clone()])
            .unwrap_or_else(|| lifecycle.liveness_probe_ref.iter().cloned().collect());
        let parent_lane_id = lifecycle
            .parent_host_lane_key
            .as_ref()
            .and_then(|parent_key| {
                let candidates = lane_ids
                    .iter()
                    .filter(|(candidate, _)| {
                        candidate.identity.host_session_id == key.identity.host_session_id
                            && candidate.identity.host_lane_key == *parent_key
                    })
                    .map(|(_, id)| *id)
                    .collect::<BTreeSet<_>>();
                (candidates.len() == 1)
                    .then(|| candidates.into_iter().next())
                    .flatten()
            });
        let lane_sequences = receipts
            .iter()
            .filter_map(|receipt| receipt.lifecycle.as_ref())
            .map(|lifecycle| lifecycle.lane_sequence)
            .collect::<BTreeSet<_>>();
        let sequence_gaps = missing_intervals(&lane_sequences, None, None)
            .into_iter()
            .map(|interval| SequenceGap {
                first_sequence: interval.first,
                last_sequence: interval.last,
            })
            .collect::<Vec<_>>();
        let eligible_observation_ids = receipts
            .iter()
            .map(|receipt| receipt.source_observation_id)
            .collect::<BTreeSet<_>>();
        let (tool_calls, tool_results, unmatched_calls, unmatched_results) =
            pairing_for_group(state, groups, &key, &eligible_observation_ids);
        let mut resolved = resolve_capture(CaptureResolverInput {
            execution_lane_id: lane_id,
            capture_receipt_revision_id: CaptureReceiptId::new_v7(),
            previous_lane: previous_lane.clone(),
            previous_receipt: previous_receipt.clone(),
            host_session_id: key.identity.host_session_id.clone(),
            agent_id: key.identity.agent_id.clone(),
            host_lane_key: key.identity.host_lane_key.clone(),
            incarnation_ref: key.incarnation_ref.clone(),
            parent_lane_id,
            parent_host_lane_key: lifecycle.parent_host_lane_key.clone(),
            spawn_event_ref: lifecycle.spawn_event_ref.clone(),
            terminal_event_ref: lifecycle.terminal_event_ref.clone(),
            terminal_kind: lifecycle.terminal_kind,
            host_final_return: lifecycle.host_final_return,
            parent_session_end_seen: lifecycle.parent_session_end_ref.is_some(),
            liveness_state,
            liveness_probe_refs: liveness_refs,
            all_sources_closed,
            source_closed_refs: summaries
                .iter()
                .flat_map(|source| source.close_refs.iter().cloned())
                .collect(),
            source_close_watermark_refs: proof
                .as_ref()
                .map(SourceCloseReconciliation::close_watermark_refs)
                .unwrap_or_default(),
            source_close_reconciliation_refs: reconciliation_refs.into_iter().collect(),
            source_reconciliation_complete,
            adapter_manifest_ids: manifest
                .manifests
                .iter()
                .map(|manifest| manifest.adapter_manifest_id.clone())
                .collect(),
            eligible_event_manifest_refs: manifest
                .manifests
                .iter()
                .flat_map(|manifest| manifest.eligible_event_manifest_refs.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            source_revision_refs: summaries
                .iter()
                .map(|source| source.source_ref.clone())
                .collect(),
            manifest_coverage: manifest.coverage,
            required_for_full: manifest.required,
            observed_capabilities: manifest.observed,
            admission_failure_observability: weakest_observability(&manifest.manifests),
            independent_reconciliation: independent_value.is_some(),
            admission_failure_evidence_refs: gap_refs.iter().cloned().collect(),
            identity_strength: weakest_identity(&receipts),
            child_session_id: manifest.child_session_id,
            first_sequence: lane_sequences.first().copied(),
            last_sequence: lane_sequences.last().copied(),
            sequence_gaps,
            capture_gap_marker_refs: gap_refs.into_iter().collect(),
            unresolved_gap_marker_refs: unresolved_gap_refs,
            capture_outage_interval_refs: outage_ids,
            unresolved_outage_interval_refs: unresolved_outages,
            tool_calls_seen: tool_calls,
            tool_results_seen: tool_results,
            unmatched_tool_call_ids: unmatched_calls,
            unmatched_tool_result_ids: unmatched_results,
            payload_truncations: receipts
                .iter()
                .filter(|receipt| {
                    receipt.capture_completeness
                        != evertrace_domain::evidence::CaptureCompleteness::Complete
                })
                .map(|receipt| receipt.source_receipt_id.to_string())
                .collect(),
            redaction_refs: receipts
                .iter()
                .filter(|receipt| receipt.archive_mode == SourceArchiveMode::Redacted)
                .map(|receipt| receipt.source_receipt_id.to_string())
                .collect(),
            corrupt_payload_refs: Vec::new(),
            unavailable_payload_refs: Vec::new(),
            unsupported_record_types: receipts
                .iter()
                .filter_map(|receipt| {
                    receipt
                        .unsupported_record_classification
                        .map(|kind| format!("{kind:?}"))
                })
                .collect(),
            causal_race: false,
            ordering_best_effort: manifest.manifests.iter().any(|manifest| {
                manifest.recovery_ordering
                    != evertrace_codex::adapter_manifest::RecoveryOrdering::FencedHost
            }),
            reasoning_visibility: receipts
                .iter()
                .filter_map(|receipt| receipt.lifecycle.as_ref())
                .flat_map(|lifecycle| lifecycle.reasoning_visibility.clone())
                .collect(),
            import_watermark: import_frontier,
            delegated_goal_ref: lifecycle.delegated_goal_ref.clone(),
            delegated_target_refs: lifecycle.delegated_target_refs.clone(),
            delegated_acceptance_refs: lifecycle.delegated_acceptance_refs.clone(),
            operation_ids: operation_ids.get(&key).cloned().unwrap_or_default(),
            correction_reason: previous_lane
                .as_ref()
                .filter(|lane| {
                    lane.status == evertrace_domain::work::LaneStatus::InterruptedUnconfirmed
                        && lifecycle.terminal_kind.is_some()
                })
                .map(|_| "late_terminal_evidence".into()),
        })
        .map_err(|_| ReconcileError::Domain)?;
        resolved.0.event_watermark = lane_sequences.last().copied().unwrap_or(0);
        resolved.0.validate().map_err(|_| ReconcileError::Domain)?;
        let (lane, receipt) = resolved;
        if capture_changed(
            previous_lane.as_ref(),
            previous_receipt.as_ref(),
            &lane,
            &receipt,
        ) {
            payloads.push(JournalPayload::ExecutionLaneRecorded(Box::new(
                lane.clone(),
            )));
            payloads.push(JournalPayload::CaptureReceiptRecorded(Box::new(
                receipt.clone(),
            )));
            state.execution_lanes.insert(lane_id, lane);
            state.capture_receipts.insert(lane_id, receipt);
            progress.lane_revisions_recorded += 1;
            progress.receipt_revisions_recorded += 1;
        }
    }
    Ok(())
}

fn weakest_observability(
    manifests: &[&AdapterCapabilityManifest],
) -> AdmissionFailureObservability {
    manifests.iter().fold(
        AdmissionFailureObservability::Complete,
        |current, manifest| {
            let next = match manifest.admission_failure_observability {
                ManifestObservability::Complete => AdmissionFailureObservability::Complete,
                ManifestObservability::Reconcilable => AdmissionFailureObservability::Reconcilable,
                ManifestObservability::BestEffort => AdmissionFailureObservability::BestEffort,
                ManifestObservability::Unavailable => AdmissionFailureObservability::Unavailable,
            };
            if observability_rank(next) > observability_rank(current) {
                next
            } else {
                current
            }
        },
    )
}

const fn observability_rank(value: AdmissionFailureObservability) -> u8 {
    match value {
        AdmissionFailureObservability::Complete => 0,
        AdmissionFailureObservability::Reconcilable => 1,
        AdmissionFailureObservability::BestEffort => 2,
        AdmissionFailureObservability::Unavailable => 3,
    }
}

fn weakest_identity(receipts: &[&SourceReceipt]) -> IdentityStrength {
    receipts
        .iter()
        .fold(IdentityStrength::StableNative, |current, receipt| {
            if identity_rank(receipt.identity_strength) > identity_rank(current) {
                receipt.identity_strength
            } else {
                current
            }
        })
}

const fn identity_rank(value: IdentityStrength) -> u8 {
    match value {
        IdentityStrength::StableNative => 0,
        IdentityStrength::StableSourceSequence => 1,
        IdentityStrength::SynthesizedBestEffort => 2,
    }
}

fn capture_changed(
    previous_lane: Option<&ExecutionLane>,
    previous_receipt: Option<&CaptureReceipt>,
    lane: &ExecutionLane,
    receipt: &CaptureReceipt,
) -> bool {
    let (Some(previous_lane), Some(previous_receipt)) = (previous_lane, previous_receipt) else {
        return true;
    };
    let mut normalized_lane = lane.clone();
    normalized_lane.lane_revision = previous_lane.lane_revision;
    normalized_lane.predecessor_revision = previous_lane.predecessor_revision;
    normalized_lane.active_capture_receipt_revision_id =
        previous_lane.active_capture_receipt_revision_id;
    let mut normalized_receipt = receipt.clone();
    normalized_receipt.capture_receipt_revision_id = previous_receipt.capture_receipt_revision_id;
    normalized_receipt.predecessor_revision_id = previous_receipt.predecessor_revision_id;
    normalized_lane != *previous_lane || normalized_receipt != *previous_receipt
}

fn reconciliation_command(
    input: &ReconcileInput,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, ReconcileError> {
    let events = payloads
        .into_iter()
        .map(|payload| JournalEventDraft {
            occurred_at_us: input.occurred_at_us,
            source_kind: SourceKind::System,
            scope: EventScope::default(),
            causation_id: None,
            correlation_id: None,
            effective_config_hash: input.effective_config_hash,
            algorithm_revision: input.algorithm_revision.clone(),
            payload,
        })
        .collect();
    JournalCommand::new(CommandId::new_v7(), events).map_err(|_| ReconcileError::Domain)
}

fn gap_was_propagated(state: &CurrentCaptureState, marker_id: &str) -> bool {
    let Some(gap) = state.capture_gaps.get(marker_id) else {
        return false;
    };
    let affected_identities = identities_for_gap(state, gap);
    let affected = state
        .execution_lanes
        .values()
        .filter(|lane| affected_identities.contains(&LaneIdentityKey::from_lane(lane)))
        .collect::<Vec<_>>();
    !affected.is_empty()
        && affected.iter().all(|lane| {
            state
                .capture_receipts
                .get(&lane.execution_lane_id)
                .is_some_and(|receipt| receipt.capture_gap_marker_refs.contains(&gap.marker_id))
        })
}

fn map_reconcile_writer(error: WriterActorError) -> ReconcileError {
    match error {
        WriterActorError::InvalidInput | WriterActorError::IdempotencyConflict => {
            ReconcileError::Domain
        }
        WriterActorError::StoreCorrupt => ReconcileError::Projection,
        WriterActorError::StaleFrontier => ReconcileError::StaleFrontier,
        WriterActorError::Stopped | WriterActorError::Store => ReconcileError::Commit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle(spawn_event_ref: &str) -> evertrace_domain::work::LaneLifecycleEvidence {
        evertrace_domain::work::LaneLifecycleEvidence {
            host_session_id: "session-a".into(),
            agent_id: "agent-a".into(),
            incarnation_ref: None,
            child_session_id: Some("same-child".into()),
            host_lane_key: "lane-a".into(),
            parent_host_lane_key: None,
            spawn_event_ref: Some(spawn_event_ref.into()),
            terminal_event_ref: None,
            terminal_kind: None,
            host_final_return: false,
            source_close_ref: None,
            parent_session_end_ref: None,
            liveness_probe_ref: None,
            liveness_state: LivenessState::Unknown,
            lane_sequence: 1,
            adapter_manifest_ref: "manifest-a".into(),
            eligible_event_manifest_ref: "events-a".into(),
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            reasoning_visibility: Vec::new(),
        }
    }

    #[test]
    fn legacy_lifecycle_never_uses_child_or_spawn_as_incarnation() {
        let first_observation = SourceObservationId::from_digest([1; 32]);
        let second_observation = SourceObservationId::from_digest([2; 32]);
        let first = lifecycle_incarnation_ref(&lifecycle("spawn-a"), first_observation);
        let second = lifecycle_incarnation_ref(&lifecycle("spawn-b"), second_observation);
        assert_eq!(first, format!("source-observation:{first_observation}"));
        assert_eq!(second, format!("source-observation:{second_observation}"));
        assert_ne!(first, second);

        let mut explicit = lifecycle("spawn-c");
        explicit.incarnation_ref = Some("incarnation-explicit".into());
        assert_eq!(
            lifecycle_incarnation_ref(&explicit, first_observation),
            "incarnation-explicit"
        );
        assert_eq!(
            lifecycle_incarnation_ref(&explicit, second_observation),
            "incarnation-explicit"
        );
    }
}
