use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    evidence::IdentityStrength,
    ids::{CaptureOutageIntervalId, CaptureReceiptId, ExecutionLaneId, OperationId},
};

pub mod attempt;
pub mod binding;
pub mod burst;
pub mod episode;
pub mod task;
pub mod workstream;

pub use attempt::*;
pub use binding::{
    ActiveWorkContext, AssignmentStatus, PrimaryWorkBinding, SecondaryBindingRole,
    SecondaryBindingTarget, SecondaryWorkBinding, WorkBindingRevision,
};
pub use burst::*;
pub use episode::*;
pub use task::{Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership};
pub use workstream::{
    ActiveLineageFoundation, CorrelationEvidence, CorrelationEvidenceKind, CorrelationResult,
    PhaseContract, PhaseKind, UnresolvedWorkstream, Workstream, WorkstreamStatus,
};

pub const CAPTURE_RESOLVER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    Returned,
    Stopped,
    Interrupted,
    InterruptedUnconfirmed,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalKind {
    Normal,
    Timeout,
    Cancelled,
    Crashed,
    SourceClosedUnconfirmed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessState {
    Live,
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    Full,
    Partial,
    Opaque,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCoverage {
    Open,
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingIntegrity {
    Complete,
    Unmatched,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadIntegrity {
    Complete,
    Redacted,
    Truncated,
    Corrupt,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingIntegrity {
    Complete,
    Gapped,
    Raced,
    BestEffort,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningVisibility {
    Raw,
    Summary,
    ExplicitRationale,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionFailureObservability {
    Complete,
    Reconcilable,
    BestEffort,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceGap {
    pub first_sequence: u64,
    pub last_sequence: u64,
}

impl SequenceGap {
    pub const fn validate(self) -> Result<(), WorkError> {
        if self.first_sequence > self.last_sequence {
            Err(WorkError::InvalidReceipt)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneLifecycleEvidence {
    pub host_session_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub incarnation_ref: Option<String>,
    #[serde(default)]
    pub child_session_id: Option<String>,
    pub host_lane_key: String,
    pub parent_host_lane_key: Option<String>,
    pub spawn_event_ref: Option<String>,
    pub terminal_event_ref: Option<String>,
    pub terminal_kind: Option<TerminalKind>,
    pub host_final_return: bool,
    pub source_close_ref: Option<String>,
    pub parent_session_end_ref: Option<String>,
    pub liveness_probe_ref: Option<String>,
    pub liveness_state: LivenessState,
    pub lane_sequence: u64,
    pub adapter_manifest_ref: String,
    pub eligible_event_manifest_ref: String,
    pub delegated_goal_ref: Option<String>,
    pub delegated_target_refs: Vec<String>,
    pub delegated_acceptance_refs: Vec<String>,
    pub reasoning_visibility: Vec<ReasoningVisibility>,
}

impl LaneLifecycleEvidence {
    pub fn validate(&self) -> Result<(), WorkError> {
        for value in [
            self.host_session_id.as_str(),
            self.agent_id.as_str(),
            self.host_lane_key.as_str(),
            self.adapter_manifest_ref.as_str(),
            self.eligible_event_manifest_ref.as_str(),
        ] {
            valid_ref(value)?;
        }
        for value in [
            self.incarnation_ref.as_deref(),
            self.parent_host_lane_key.as_deref(),
            self.child_session_id.as_deref(),
            self.spawn_event_ref.as_deref(),
            self.terminal_event_ref.as_deref(),
            self.source_close_ref.as_deref(),
            self.parent_session_end_ref.as_deref(),
            self.liveness_probe_ref.as_deref(),
            self.delegated_goal_ref.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            valid_ref(value)?;
        }
        for value in self
            .delegated_target_refs
            .iter()
            .chain(&self.delegated_acceptance_refs)
        {
            valid_ref(value)?;
        }
        require_unique(&self.delegated_target_refs)?;
        require_unique(&self.delegated_acceptance_refs)?;
        require_unique(&self.reasoning_visibility)?;
        if self.terminal_kind.is_some() != self.terminal_event_ref.is_some()
            || (self.host_final_return && self.terminal_kind != Some(TerminalKind::Normal))
            || self.terminal_kind == Some(TerminalKind::SourceClosedUnconfirmed)
        {
            return Err(WorkError::InvalidLifecycle);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLane {
    pub execution_lane_id: ExecutionLaneId,
    pub lane_revision: u32,
    pub predecessor_revision: Option<u32>,
    pub host_session_id: String,
    pub agent_id: String,
    pub host_lane_key: String,
    pub incarnation_ref: String,
    pub parent_lane_id: Option<ExecutionLaneId>,
    pub parent_host_lane_key: Option<String>,
    pub spawn_event_ref: Option<String>,
    pub terminal_event_ref: Option<String>,
    pub termination_evidence_refs: Vec<String>,
    pub delegated_goal_ref: Option<String>,
    pub delegated_target_refs: Vec<String>,
    pub delegated_acceptance_refs: Vec<String>,
    pub status: LaneStatus,
    pub terminal_kind: Option<TerminalKind>,
    pub liveness_state: LivenessState,
    pub liveness_probe_refs: Vec<String>,
    pub finalized: bool,
    pub event_watermark: u64,
    pub adapter_manifest_ids: Vec<String>,
    pub active_capture_receipt_revision_id: CaptureReceiptId,
    pub coverage_level: CoverageLevel,
    pub source_coverage: SourceCoverage,
    pub pairing_integrity: PairingIntegrity,
    pub payload_integrity: PayloadIntegrity,
    pub ordering_integrity: OrderingIntegrity,
    pub reasoning_visibility: Vec<ReasoningVisibility>,
    pub operation_ids: Vec<OperationId>,
    pub correction_reason: Option<String>,
}

impl ExecutionLane {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.lane_revision == 0
            || self.predecessor_revision
                != self
                    .lane_revision
                    .checked_sub(1)
                    .filter(|_| self.lane_revision > 1)
            || self.finalized
                != matches!(
                    self.status,
                    LaneStatus::Returned
                        | LaneStatus::Stopped
                        | LaneStatus::Interrupted
                        | LaneStatus::InterruptedUnconfirmed
                )
            || matches!(self.status, LaneStatus::Active | LaneStatus::Unresolved)
                && self.terminal_kind.is_some()
            || self.status == LaneStatus::InterruptedUnconfirmed
                && self.terminal_kind != Some(TerminalKind::SourceClosedUnconfirmed)
            || matches!(self.status, LaneStatus::Returned | LaneStatus::Stopped)
                && self.terminal_kind != Some(TerminalKind::Normal)
            || self.status == LaneStatus::Interrupted
                && !matches!(
                    self.terminal_kind,
                    Some(TerminalKind::Timeout | TerminalKind::Cancelled | TerminalKind::Crashed)
                )
            || !terminal_reference_is_valid(self.terminal_kind, self.terminal_event_ref.as_deref())
        {
            return Err(WorkError::InvalidLane);
        }
        for value in [
            self.host_session_id.as_str(),
            self.agent_id.as_str(),
            self.host_lane_key.as_str(),
            self.incarnation_ref.as_str(),
        ] {
            valid_ref(value)?;
        }
        require_unique(&self.adapter_manifest_ids)?;
        require_unique(&self.termination_evidence_refs)?;
        require_unique(&self.liveness_probe_refs)?;
        require_unique(&self.operation_ids)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceipt {
    pub capture_receipt_revision_id: CaptureReceiptId,
    pub execution_lane_id: ExecutionLaneId,
    pub predecessor_revision_id: Option<CaptureReceiptId>,
    pub adapter_manifest_ids: Vec<String>,
    pub eligible_event_manifest_refs: Vec<String>,
    pub source_revision_refs: Vec<String>,
    pub source_close_watermark_refs: Vec<String>,
    pub source_close_reconciliation_refs: Vec<String>,
    pub admission_failure_evidence_refs: Vec<String>,
    pub admission_failure_observability: AdmissionFailureObservability,
    pub identity_strength: IdentityStrength,
    pub delegation_start_seen: bool,
    pub child_session_linked: bool,
    pub child_session_id: Option<String>,
    pub parent_session_end_seen: bool,
    pub lifecycle_end_seen: bool,
    pub terminal_event_kind: Option<TerminalKind>,
    pub terminal_event_ref: Option<String>,
    pub termination_evidence_refs: Vec<String>,
    pub source_closed_refs: Vec<String>,
    pub liveness_probe_refs: Vec<String>,
    pub finalization_reason: Option<String>,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub sequence_gaps: Vec<SequenceGap>,
    pub capture_gap_marker_refs: Vec<String>,
    pub capture_outage_interval_refs: Vec<CaptureOutageIntervalId>,
    pub tool_calls_seen: Vec<String>,
    pub tool_results_seen: Vec<String>,
    pub unmatched_tool_call_ids: Vec<String>,
    pub unmatched_tool_result_ids: Vec<String>,
    pub payload_truncations: Vec<String>,
    pub redaction_refs: Vec<String>,
    pub corrupt_payload_refs: Vec<String>,
    pub unsupported_record_types: Vec<String>,
    pub import_watermark: u64,
    pub finalized: bool,
    pub coverage_level: CoverageLevel,
    pub source_coverage: SourceCoverage,
    pub pairing_integrity: PairingIntegrity,
    pub payload_integrity: PayloadIntegrity,
    pub ordering_integrity: OrderingIntegrity,
    pub reasoning_visibility: Vec<ReasoningVisibility>,
    pub exact_byte_replay: bool,
    pub resolver_version: u32,
}

impl CaptureReceipt {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.resolver_version == 0
            || self.predecessor_revision_id == Some(self.capture_receipt_revision_id)
            || self.exact_byte_replay != (self.payload_integrity == PayloadIntegrity::Complete)
            || self
                .first_sequence
                .zip(self.last_sequence)
                .is_some_and(|(first, last)| first > last)
            || self.child_session_linked != self.child_session_id.is_some()
            || !receipt_terminal_is_valid(
                self.terminal_event_kind,
                self.terminal_event_ref.as_deref(),
                self.lifecycle_end_seen,
            )
        {
            return Err(WorkError::InvalidReceipt);
        }
        require_unique(&self.adapter_manifest_ids)?;
        require_unique(&self.eligible_event_manifest_refs)?;
        require_unique(&self.source_revision_refs)?;
        require_unique(&self.capture_gap_marker_refs)?;
        require_unique(&self.capture_outage_interval_refs)?;
        require_unique(&self.sequence_gaps)?;
        require_unique(&self.reasoning_visibility)?;
        for gap in &self.sequence_gaps {
            gap.validate()?;
        }
        if let Some(child_session_id) = &self.child_session_id {
            valid_ref(child_session_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureResolverInput {
    pub execution_lane_id: ExecutionLaneId,
    pub capture_receipt_revision_id: CaptureReceiptId,
    pub previous_lane: Option<ExecutionLane>,
    pub previous_receipt: Option<CaptureReceipt>,
    pub host_session_id: String,
    pub agent_id: String,
    pub host_lane_key: String,
    pub incarnation_ref: String,
    pub parent_lane_id: Option<ExecutionLaneId>,
    pub parent_host_lane_key: Option<String>,
    pub spawn_event_ref: Option<String>,
    pub terminal_event_ref: Option<String>,
    pub terminal_kind: Option<TerminalKind>,
    pub host_final_return: bool,
    pub parent_session_end_seen: bool,
    pub liveness_state: LivenessState,
    pub liveness_probe_refs: Vec<String>,
    pub all_sources_closed: bool,
    pub source_closed_refs: Vec<String>,
    pub source_close_watermark_refs: Vec<String>,
    pub source_close_reconciliation_refs: Vec<String>,
    pub source_reconciliation_complete: bool,
    pub adapter_manifest_ids: Vec<String>,
    pub eligible_event_manifest_refs: Vec<String>,
    pub source_revision_refs: Vec<String>,
    pub manifest_coverage: Vec<CoverageLevel>,
    pub required_for_full: BTreeSet<String>,
    pub observed_capabilities: BTreeSet<String>,
    pub admission_failure_observability: AdmissionFailureObservability,
    pub independent_reconciliation: bool,
    pub admission_failure_evidence_refs: Vec<String>,
    pub identity_strength: IdentityStrength,
    pub child_session_id: Option<String>,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub sequence_gaps: Vec<SequenceGap>,
    pub capture_gap_marker_refs: Vec<String>,
    pub unresolved_gap_marker_refs: Vec<String>,
    pub capture_outage_interval_refs: Vec<CaptureOutageIntervalId>,
    pub unresolved_outage_interval_refs: Vec<CaptureOutageIntervalId>,
    pub tool_calls_seen: Vec<String>,
    pub tool_results_seen: Vec<String>,
    pub unmatched_tool_call_ids: Vec<String>,
    pub unmatched_tool_result_ids: Vec<String>,
    pub payload_truncations: Vec<String>,
    pub redaction_refs: Vec<String>,
    pub corrupt_payload_refs: Vec<String>,
    pub unavailable_payload_refs: Vec<String>,
    pub unsupported_record_types: Vec<String>,
    pub causal_race: bool,
    pub ordering_best_effort: bool,
    pub reasoning_visibility: Vec<ReasoningVisibility>,
    pub import_watermark: u64,
    pub delegated_goal_ref: Option<String>,
    pub delegated_target_refs: Vec<String>,
    pub delegated_acceptance_refs: Vec<String>,
    pub operation_ids: Vec<OperationId>,
    pub correction_reason: Option<String>,
}

pub fn resolve_capture(
    input: CaptureResolverInput,
) -> Result<(ExecutionLane, CaptureReceipt), WorkError> {
    if input.terminal_kind.is_some() != input.terminal_event_ref.is_some() {
        return Err(WorkError::InvalidLifecycle);
    }
    if input.previous_lane.is_some() != input.previous_receipt.is_some() {
        return Err(WorkError::InvalidReceipt);
    }
    if let Some(previous_lane) = &input.previous_lane
        && (previous_lane.execution_lane_id != input.execution_lane_id
            || previous_lane.host_session_id != input.host_session_id
            || previous_lane.agent_id != input.agent_id
            || previous_lane.host_lane_key != input.host_lane_key
            || previous_lane.incarnation_ref != input.incarnation_ref
            || matches!(
                (&previous_lane.spawn_event_ref, &input.spawn_event_ref),
                (Some(previous), Some(current)) if previous != current
            ))
    {
        return Err(WorkError::InvalidLane);
    }
    if let Some(previous_receipt) = &input.previous_receipt
        && (previous_receipt.execution_lane_id != input.execution_lane_id
            || previous_receipt.capture_receipt_revision_id == input.capture_receipt_revision_id)
    {
        return Err(WorkError::InvalidReceipt);
    }
    if let (Some(previous_lane), Some(previous_receipt)) =
        (&input.previous_lane, &input.previous_receipt)
        && previous_lane.active_capture_receipt_revision_id
            != previous_receipt.capture_receipt_revision_id
    {
        return Err(WorkError::InvalidReceipt);
    }
    let coverage_level = if input.manifest_coverage.is_empty()
        || input.manifest_coverage.contains(&CoverageLevel::Opaque)
    {
        CoverageLevel::Opaque
    } else if input.manifest_coverage.contains(&CoverageLevel::Partial)
        || input.child_session_id.is_none()
        || !input
            .required_for_full
            .is_subset(&input.observed_capabilities)
    {
        CoverageLevel::Partial
    } else {
        CoverageLevel::Full
    };
    let source_coverage = if input.source_revision_refs.is_empty() {
        SourceCoverage::Unavailable
    } else if !input.all_sources_closed {
        SourceCoverage::Open
    } else if input.eligible_event_manifest_refs.is_empty()
        || !input.source_reconciliation_complete
        || !input.unresolved_gap_marker_refs.is_empty()
        || !input.unresolved_outage_interval_refs.is_empty()
        || (!matches!(
            input.admission_failure_observability,
            AdmissionFailureObservability::Complete | AdmissionFailureObservability::Reconcilable
        ) && !input.independent_reconciliation)
        || !input.unsupported_record_types.is_empty()
    {
        SourceCoverage::Partial
    } else {
        SourceCoverage::Complete
    };
    let pairing_integrity = if input.tool_calls_seen.is_empty()
        && input.tool_results_seen.is_empty()
    {
        PairingIntegrity::Unavailable
    } else if input.unmatched_tool_call_ids.is_empty() && input.unmatched_tool_result_ids.is_empty()
    {
        PairingIntegrity::Complete
    } else {
        PairingIntegrity::Unmatched
    };
    let payload_integrity = if !input.corrupt_payload_refs.is_empty() {
        PayloadIntegrity::Corrupt
    } else if !input.unavailable_payload_refs.is_empty()
        || !input.unresolved_gap_marker_refs.is_empty()
    {
        PayloadIntegrity::Unavailable
    } else if !input.payload_truncations.is_empty() {
        PayloadIntegrity::Truncated
    } else if !input.redaction_refs.is_empty() {
        PayloadIntegrity::Redacted
    } else {
        PayloadIntegrity::Complete
    };
    let ordering_integrity = if input.source_revision_refs.is_empty() {
        OrderingIntegrity::Unavailable
    } else if !input.sequence_gaps.is_empty() || !input.unresolved_outage_interval_refs.is_empty() {
        OrderingIntegrity::Gapped
    } else if input.causal_race {
        OrderingIntegrity::Raced
    } else if input.ordering_best_effort {
        OrderingIntegrity::BestEffort
    } else {
        OrderingIntegrity::Complete
    };
    let previous_status = input
        .previous_lane
        .as_ref()
        .map_or(LaneStatus::Active, |lane| lane.status);
    let (status, terminal_kind, finalized, finalization_reason) = match input.terminal_kind {
        Some(TerminalKind::Normal) => (
            if input.host_final_return {
                LaneStatus::Returned
            } else {
                LaneStatus::Stopped
            },
            input.terminal_kind,
            true,
            Some(
                if input.host_final_return {
                    "host_final_return"
                } else {
                    "explicit_terminal"
                }
                .into(),
            ),
        ),
        Some(kind @ (TerminalKind::Timeout | TerminalKind::Cancelled | TerminalKind::Crashed)) => (
            LaneStatus::Interrupted,
            Some(kind),
            true,
            Some("explicit_interruption".into()),
        ),
        Some(TerminalKind::SourceClosedUnconfirmed) => return Err(WorkError::InvalidLifecycle),
        None if input.all_sources_closed && input.liveness_state == LivenessState::Absent => (
            LaneStatus::InterruptedUnconfirmed,
            Some(TerminalKind::SourceClosedUnconfirmed),
            true,
            Some("source_closed_liveness_absent".into()),
        ),
        None if input.all_sources_closed => (LaneStatus::Unresolved, None, false, None),
        None if input.parent_session_end_seen => (LaneStatus::Unresolved, None, false, None),
        None if matches!(previous_status, LaneStatus::Unresolved | LaneStatus::Active) => {
            (previous_status, None, false, None)
        }
        None => return Err(WorkError::FinalizedLaneCannotReopen),
    };
    if input
        .previous_lane
        .as_ref()
        .is_some_and(|lane| lane.finalized && !finalized)
    {
        return Err(WorkError::FinalizedLaneCannotReopen);
    }
    let predecessor_revision_id = input
        .previous_receipt
        .as_ref()
        .map(|receipt| receipt.capture_receipt_revision_id);
    let lane_revision = input
        .previous_lane
        .as_ref()
        .map_or(1, |lane| lane.lane_revision + 1);
    let predecessor_revision = input.previous_lane.as_ref().map(|lane| lane.lane_revision);
    let lifecycle_end_seen = input.terminal_kind.is_some();
    let exact_byte_replay = payload_integrity == PayloadIntegrity::Complete;
    let receipt = CaptureReceipt {
        capture_receipt_revision_id: input.capture_receipt_revision_id,
        execution_lane_id: input.execution_lane_id,
        predecessor_revision_id,
        adapter_manifest_ids: input.adapter_manifest_ids.clone(),
        eligible_event_manifest_refs: input.eligible_event_manifest_refs,
        source_revision_refs: input.source_revision_refs,
        source_close_watermark_refs: input.source_close_watermark_refs,
        source_close_reconciliation_refs: input.source_close_reconciliation_refs,
        admission_failure_evidence_refs: input.admission_failure_evidence_refs,
        admission_failure_observability: input.admission_failure_observability,
        identity_strength: input.identity_strength,
        delegation_start_seen: input.spawn_event_ref.is_some(),
        child_session_linked: input.child_session_id.is_some(),
        child_session_id: input.child_session_id,
        parent_session_end_seen: input.parent_session_end_seen,
        lifecycle_end_seen,
        terminal_event_kind: terminal_kind,
        terminal_event_ref: input.terminal_event_ref.clone(),
        termination_evidence_refs: input
            .terminal_event_ref
            .iter()
            .cloned()
            .chain(input.liveness_probe_refs.iter().cloned())
            .collect(),
        source_closed_refs: input.source_closed_refs,
        liveness_probe_refs: input.liveness_probe_refs.clone(),
        finalization_reason,
        first_sequence: input.first_sequence,
        last_sequence: input.last_sequence,
        sequence_gaps: input.sequence_gaps,
        capture_gap_marker_refs: input.capture_gap_marker_refs,
        capture_outage_interval_refs: input.capture_outage_interval_refs,
        tool_calls_seen: input.tool_calls_seen,
        tool_results_seen: input.tool_results_seen,
        unmatched_tool_call_ids: input.unmatched_tool_call_ids,
        unmatched_tool_result_ids: input.unmatched_tool_result_ids,
        payload_truncations: input.payload_truncations,
        redaction_refs: input.redaction_refs,
        corrupt_payload_refs: input.corrupt_payload_refs,
        unsupported_record_types: input.unsupported_record_types,
        import_watermark: input.import_watermark,
        finalized,
        coverage_level,
        source_coverage,
        pairing_integrity,
        payload_integrity,
        ordering_integrity,
        reasoning_visibility: unique_sorted(input.reasoning_visibility),
        exact_byte_replay,
        resolver_version: CAPTURE_RESOLVER_VERSION,
    };
    let lane = ExecutionLane {
        execution_lane_id: input.execution_lane_id,
        lane_revision,
        predecessor_revision,
        host_session_id: input.host_session_id,
        agent_id: input.agent_id,
        host_lane_key: input.host_lane_key,
        incarnation_ref: input.incarnation_ref,
        parent_lane_id: input.parent_lane_id,
        parent_host_lane_key: input.parent_host_lane_key,
        spawn_event_ref: input.spawn_event_ref,
        terminal_event_ref: receipt.terminal_event_ref.clone(),
        termination_evidence_refs: receipt.termination_evidence_refs.clone(),
        delegated_goal_ref: input.delegated_goal_ref,
        delegated_target_refs: input.delegated_target_refs,
        delegated_acceptance_refs: input.delegated_acceptance_refs,
        status,
        terminal_kind,
        liveness_state: input.liveness_state,
        liveness_probe_refs: input.liveness_probe_refs,
        finalized,
        event_watermark: input.import_watermark,
        adapter_manifest_ids: input.adapter_manifest_ids,
        active_capture_receipt_revision_id: input.capture_receipt_revision_id,
        coverage_level,
        source_coverage,
        pairing_integrity,
        payload_integrity,
        ordering_integrity,
        reasoning_visibility: receipt.reasoning_visibility.clone(),
        operation_ids: input.operation_ids,
        correction_reason: input.correction_reason,
    };
    lane.validate()?;
    receipt.validate()?;
    Ok((lane, receipt))
}

fn valid_ref(value: &str) -> Result<(), WorkError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(WorkError::InvalidReference)
    } else {
        Ok(())
    }
}

fn require_unique<T: Ord + Clone>(values: &[T]) -> Result<(), WorkError> {
    if values.iter().cloned().collect::<BTreeSet<_>>().len() != values.len() {
        Err(WorkError::Duplicate)
    } else {
        Ok(())
    }
}

fn unique_sorted<T: Ord>(values: Vec<T>) -> Vec<T> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn terminal_reference_is_valid(kind: Option<TerminalKind>, event_ref: Option<&str>) -> bool {
    match kind {
        Some(TerminalKind::SourceClosedUnconfirmed) => event_ref.is_none(),
        Some(_) => event_ref.is_some(),
        None => event_ref.is_none(),
    }
}

fn receipt_terminal_is_valid(
    kind: Option<TerminalKind>,
    event_ref: Option<&str>,
    lifecycle_end_seen: bool,
) -> bool {
    match kind {
        Some(TerminalKind::SourceClosedUnconfirmed) => event_ref.is_none() && !lifecycle_end_seen,
        Some(_) => event_ref.is_some() && lifecycle_end_seen,
        None => event_ref.is_none() && !lifecycle_end_seen,
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkError {
    #[error("task or workstream identity is invalid")]
    InvalidWorkIdentity,
    #[error("work reference is invalid")]
    InvalidReference,
    #[error("work collection contains duplicates")]
    Duplicate,
    #[error("lane lifecycle evidence is invalid")]
    InvalidLifecycle,
    #[error("execution lane revision is invalid")]
    InvalidLane,
    #[error("capture receipt revision is invalid")]
    InvalidReceipt,
    #[error("a finalized execution lane cannot be reopened")]
    FinalizedLaneCannotReopen,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn resolver_input() -> CaptureResolverInput {
        let required = strings(&[
            "child_session_id",
            "child_tool_call",
            "child_tool_result",
            "child_final_result",
        ])
        .into_iter()
        .collect::<BTreeSet<_>>();
        CaptureResolverInput {
            execution_lane_id: ExecutionLaneId::new_v7(),
            capture_receipt_revision_id: CaptureReceiptId::new_v7(),
            previous_lane: None,
            previous_receipt: None,
            host_session_id: "session-a".into(),
            agent_id: "agent-a".into(),
            host_lane_key: "lane-a".into(),
            incarnation_ref: "incarnation-a".into(),
            parent_lane_id: None,
            parent_host_lane_key: None,
            spawn_event_ref: Some("spawn-a".into()),
            terminal_event_ref: Some("terminal-a".into()),
            terminal_kind: Some(TerminalKind::Normal),
            host_final_return: false,
            parent_session_end_seen: false,
            liveness_state: LivenessState::Absent,
            liveness_probe_refs: strings(&["liveness-a"]),
            all_sources_closed: true,
            source_closed_refs: strings(&["close-a"]),
            source_close_watermark_refs: strings(&["watermark-a"]),
            source_close_reconciliation_refs: strings(&["reconciliation-a"]),
            source_reconciliation_complete: true,
            adapter_manifest_ids: strings(&["manifest-a"]),
            eligible_event_manifest_refs: strings(&["eligible-a"]),
            source_revision_refs: strings(&["source-a"]),
            manifest_coverage: vec![CoverageLevel::Full],
            required_for_full: required.clone(),
            observed_capabilities: required,
            admission_failure_observability: AdmissionFailureObservability::Complete,
            independent_reconciliation: false,
            admission_failure_evidence_refs: Vec::new(),
            identity_strength: IdentityStrength::StableNative,
            child_session_id: Some("child-session-a".into()),
            first_sequence: Some(1),
            last_sequence: Some(2),
            sequence_gaps: Vec::new(),
            capture_gap_marker_refs: Vec::new(),
            unresolved_gap_marker_refs: Vec::new(),
            capture_outage_interval_refs: Vec::new(),
            unresolved_outage_interval_refs: Vec::new(),
            tool_calls_seen: strings(&["call-a"]),
            tool_results_seen: strings(&["call-a"]),
            unmatched_tool_call_ids: Vec::new(),
            unmatched_tool_result_ids: Vec::new(),
            payload_truncations: Vec::new(),
            redaction_refs: Vec::new(),
            corrupt_payload_refs: Vec::new(),
            unavailable_payload_refs: Vec::new(),
            unsupported_record_types: Vec::new(),
            causal_race: false,
            ordering_best_effort: false,
            reasoning_visibility: Vec::new(),
            import_watermark: 2,
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            operation_ids: Vec::new(),
            correction_reason: None,
        }
    }

    #[test]
    fn source_closed_unconfirmed_keeps_liveness_separate_from_terminal_evidence() {
        let mut input = resolver_input();
        input.terminal_event_ref = None;
        input.terminal_kind = None;
        input.liveness_probe_refs = strings(&["confirmed-absent-a"]);
        let (lane, receipt) = resolve_capture(input).unwrap();

        assert_eq!(lane.status, LaneStatus::InterruptedUnconfirmed);
        assert_eq!(
            lane.terminal_kind,
            Some(TerminalKind::SourceClosedUnconfirmed)
        );
        assert_eq!(lane.terminal_event_ref, None);
        assert!(!receipt.lifecycle_end_seen);
        assert_eq!(receipt.terminal_event_ref, None);
        assert_eq!(
            receipt.liveness_probe_refs,
            strings(&["confirmed-absent-a"])
        );
        assert_eq!(
            receipt.termination_evidence_refs,
            strings(&["confirmed-absent-a"])
        );

        let mut forged_terminal = receipt.clone();
        forged_terminal.terminal_event_ref = Some("liveness-is-not-terminal".into());
        assert_eq!(forged_terminal.validate(), Err(WorkError::InvalidReceipt));

        let mut missing_explicit_ref = receipt;
        missing_explicit_ref.terminal_event_kind = Some(TerminalKind::Normal);
        missing_explicit_ref.lifecycle_end_seen = true;
        assert_eq!(
            missing_explicit_ref.validate(),
            Err(WorkError::InvalidReceipt)
        );
    }

    #[test]
    fn child_session_is_explicit_and_never_inferred_from_agent_id() {
        let (_, full) = resolve_capture(resolver_input()).unwrap();
        assert_eq!(full.coverage_level, CoverageLevel::Full);
        assert_eq!(full.child_session_id.as_deref(), Some("child-session-a"));
        assert_ne!(full.child_session_id.as_deref(), Some("agent-a"));

        let mut missing = resolver_input();
        missing.child_session_id = None;
        let (_, degraded) = resolve_capture(missing).unwrap();
        assert_eq!(degraded.child_session_id, None);
        assert!(!degraded.child_session_linked);
        assert_eq!(degraded.coverage_level, CoverageLevel::Partial);
    }

    #[test]
    fn successor_rejects_identity_drift_and_self_predecessor() {
        let (lane, receipt) = resolve_capture(resolver_input()).unwrap();
        let mut successor = resolver_input();
        successor.execution_lane_id = lane.execution_lane_id;
        successor.capture_receipt_revision_id = CaptureReceiptId::new_v7();
        successor.previous_lane = Some(lane);
        successor.previous_receipt = Some(receipt.clone());
        successor.host_session_id = "different-session".into();
        assert_eq!(resolve_capture(successor), Err(WorkError::InvalidLane));

        let mut invalid_receipt = receipt;
        invalid_receipt.predecessor_revision_id = Some(invalid_receipt.capture_receipt_revision_id);
        assert_eq!(invalid_receipt.validate(), Err(WorkError::InvalidReceipt));
    }

    #[test]
    fn finalized_successor_cannot_become_unresolved() {
        let (lane, receipt) = resolve_capture(resolver_input()).unwrap();
        let mut successor = resolver_input();
        successor.execution_lane_id = lane.execution_lane_id;
        successor.capture_receipt_revision_id = CaptureReceiptId::new_v7();
        successor.previous_lane = Some(lane);
        successor.previous_receipt = Some(receipt);
        successor.terminal_event_ref = None;
        successor.terminal_kind = None;
        successor.liveness_state = LivenessState::Unknown;
        assert_eq!(
            resolve_capture(successor),
            Err(WorkError::FinalizedLaneCannotReopen)
        );
    }
}
