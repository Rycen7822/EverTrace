use std::collections::{BTreeMap, BTreeSet};

use arrow_array::RecordBatchIterator;
use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{
        CaptureGapMarkerEvidence, CaptureOutageInterval, EvidenceSurface, HostOccurrence,
        Operation, ScopeEffect, SourceObservation, SourceReceipt, hex,
    },
    ids::{
        AtomId, AttemptId, CaptureOutageIntervalId, CompetingAttemptGroupId, ExecutionLaneId,
        ExperimentRunId, HostOccurrenceId, IntegrationEventId, JobId, OperationBurstId,
        OperationId, ProcedureId, ProcedureNegativeEvidenceId, ProcedureUsageId,
        RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, RepositoryId,
        ResultEvidenceId, RevisionProposalId, ScopeEffectId, SourceObservationId, SourceReceiptId,
        TaskId, WorkArtifactId, WorkBindingRevisionId, WorkEpisodeId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId, WorktreeTransitionId,
    },
    procedure::{ProcedureRevision, ProcedureUsageRevision},
    repository::{
        IntegrationEvent, LineageAssessment, RecoveryApplication, RecoveryBundle,
        RecoveryCaptureRequest, RepositoryInstance, WorktreeInstance, WorktreeSnapshot,
        WorktreeTransition,
    },
    revision::RevisionId,
    semantic::{
        Atom, EvidenceCompleteness, ParserStatus, ResultEvidence, ResultScope, RevisionProposal,
        VerifierStatus,
    },
    work::{
        ActiveWorkContext, AssignmentStatus, Attempt, AttemptAdoptionStatus, AttemptBindingStatus,
        AttemptExecutionStatus, AttemptLifecycleStatus, AttemptOutcomeState, AttemptVerification,
        CaptureReceipt, CompetingAttemptGroup, CompetingResolutionStatus, ExecutionLane,
        ExperimentRun, LaneStatus, OperationBurst, ResumeStateAssessment, RunContractValidity,
        RunExecutionStatus, RunObservability, SegmentationCorrection, SourceCoverage, Task,
        TaskIdentityConfidence, WorkArtifact, WorkBindingRevision, WorkCheckpoint, WorkEpisode,
        Workstream,
    },
};
use lancedb::Table;

use crate::{
    command::{
        ATOM_RECORDED_EVENT_TYPE, DirtyTarget, DurableJob, JobStatus, JobTerminalReason,
        JournalCommand, JournalPayload, NormalizationWatermark, ObjectFamily, OutboxEntry,
        SourceCloseDecision, SourceCloseReconciliation, SourceIngestWatermark, SourceKind,
        SourceRevisionRecorded, StoreError, WatermarkAdvanced, source_revision_ref,
    },
    journal::{
        JournalRow, read_all_journal_rows, read_journal_after, read_journal_frontier,
        validate_journal_rows,
    },
    objects::{
        OBJECTS_CHECKPOINT_ID, ObjectRow, ObjectRowClass, ObjectRowKind, objects_batch,
        validate_objects_table,
    },
};

mod autoresearch;
mod procedure;
mod procedure_effect;
mod procedure_validation;
mod recall_ledger;
#[path = "recall_projection.rs"]
mod recall_projection;
mod recovery;
mod s23;
mod segmentation;
mod semantic;
pub(crate) mod synthesis;
pub use autoresearch::AutoresearchCurrentView;
use autoresearch::{record_artifact, record_result, record_run};
pub use recovery::{RecoveryCurrentState, RecoveryCurrentView};
pub use segmentation::{
    EpisodeCurrentView, OperationBurstCurrentView, SegmentationCurrentState,
    SegmentationCurrentView,
};
use segmentation::{
    record_checkpoint, record_correction, record_episode, record_operation_burst,
    validate_episode_relations,
};
pub use semantic::SemanticCurrentView;

pub const RECALL_TRIGGER_INDEX_KIND: &str = recall_projection::RECALL_TRIGGER_INDEX_KIND;

pub fn recall_trigger_contract(
    row: &ObjectRow,
) -> Result<Option<evertrace_domain::recall::FutureCueContract>, StoreError> {
    recall_projection::contract(row)
}

pub fn recall_need(
    row: &ObjectRow,
) -> Result<Option<evertrace_domain::recall::RecallNeed>, StoreError> {
    recall_ledger::need(row)
}

pub(crate) fn l3_core_projection(row: &ObjectRow) -> Result<bool, StoreError> {
    s23::S23State::restore_projection(row)
}

pub(crate) fn wiki_projection(
    row: &ObjectRow,
) -> Result<Option<evertrace_domain::semantic::WikiProjection>, StoreError> {
    synthesis::restore_wiki_projection(row)
}

pub(crate) fn procedure_context_effect(
    row: &ObjectRow,
) -> Result<Option<evertrace_domain::procedure::ProcedureContextEffectProjection>, StoreError> {
    procedure_effect::restore(row)
}

const PROJECTION_GENERATION: u64 = 1;
// S10 fail-closed safety ceiling. Pagination/cursors belong to the later S23 owner.
const MAX_S10_RECONCILIATION_DEPENDENCIES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionSnapshot {
    pub frontier: u64,
    pub rows: Vec<ObjectRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSchedulerView {
    pub frontier: u64,
    pub dirty: Vec<DirtyTarget>,
    pub outbox: Vec<OutboxEntry>,
    pub jobs: Vec<DurableJob>,
}

impl RuntimeSchedulerView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut dirty = BTreeMap::new();
        let mut outbox = BTreeMap::new();
        let mut jobs = BTreeMap::new();
        for row in snapshot.data_rows() {
            if row.row_class != Some(ObjectRowClass::Runtime) {
                continue;
            }
            let Some(json) = row.payload_json.as_deref() else {
                return Err(StoreError::StoreCorrupt);
            };
            let payload: JournalPayload =
                serde_json::from_str(json).map_err(|_| StoreError::StoreCorrupt)?;
            payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::DirtyTarget(value) => {
                    if dirty.insert(value.stable_key(), value).is_some() {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                JournalPayload::OutboxEnqueued(value) => {
                    if outbox.insert(value.outbox_id.clone(), value).is_some() {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                JournalPayload::JobState(value) => {
                    if jobs.insert(value.job_id, value).is_some() {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            frontier: snapshot.frontier,
            dirty: dirty.into_values().collect(),
            outbox: outbox.into_values().collect(),
            jobs: jobs.into_values().collect(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcedureEffectCurrentFacts {
    pub frontier: u64,
    pub procedures: BTreeMap<evertrace_domain::revision::RevisionId, (ProcedureRevision, u64)>,
    pub current_procedures: BTreeMap<ProcedureId, evertrace_domain::revision::RevisionId>,
    pub usages: BTreeMap<ProcedureUsageId, (ProcedureUsageRevision, u64)>,
    pub tasks: BTreeMap<TaskId, (Task, u64)>,
    pub attempts: BTreeMap<AttemptId, (Attempt, u64)>,
    pub runs: BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    pub results: BTreeMap<evertrace_domain::revision::RevisionId, (ResultEvidence, u64)>,
    pub current_results: BTreeMap<ResultEvidenceId, evertrace_domain::revision::RevisionId>,
    pub episodes: BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    pub worktrees: BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    pub snapshots: BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    pub artifacts: BTreeMap<evertrace_domain::revision::RevisionId, (WorkArtifact, u64)>,
    pub current_artifacts: BTreeMap<WorkArtifactId, evertrace_domain::revision::RevisionId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallCurrentContext {
    pub frontier: u64,
    pub task: Task,
    pub workstream: Workstream,
    pub execution_lane: ExecutionLane,
    pub episode: WorkEpisode,
    pub checkpoint: WorkCheckpoint,
    pub previous_checkpoint: Option<WorkCheckpoint>,
    pub binding: WorkBindingRevision,
    pub atoms: Vec<RecallCurrentAtom>,
    pub needs: Vec<evertrace_domain::recall::RecallNeed>,
    pub last_presentation_attempts:
        BTreeMap<evertrace_domain::ids::RecallNeedId, evertrace_domain::ids::PresentationAttemptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallCurrentAtom {
    pub atom: Atom,
    pub source_event_seq: u64,
}

#[derive(Clone, Debug)]
pub struct RecoveryEvidenceCurrentView {
    frontier: u64,
    receipts: BTreeMap<SourceReceiptId, SourceReceipt>,
    observations: BTreeMap<SourceObservationId, SourceObservation>,
}

impl RecoveryEvidenceCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            receipts: BTreeMap::new(),
            observations: BTreeMap::new(),
        };
        for row in snapshot.data_rows() {
            let Some(kind) = row.object_kind.as_deref() else {
                continue;
            };
            if !matches!(kind, "source_receipt" | "source_observation") {
                continue;
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::SourceReceiptRecorded(value) if kind == "source_receipt" => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    if view
                        .receipts
                        .insert(value.source_receipt_id, *value)
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                JournalPayload::SourceObservationRecorded(value)
                    if kind == "source_observation" =>
                {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    if view
                        .observations
                        .insert(value.source_observation_id, *value)
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        Ok(view)
    }

    pub const fn frontier(&self) -> u64 {
        self.frontier
    }

    pub fn observation(&self, id: SourceObservationId) -> Option<&SourceObservation> {
        self.observations.get(&id)
    }

    pub fn receipt_for_observation(&self, id: SourceObservationId) -> Option<&SourceReceipt> {
        let observation = self.observation(id)?;
        self.receipts
            .get(&observation.source_receipt_ref)
            .filter(|receipt| receipt.source_observation_id == id)
    }
}

impl ProjectionSnapshot {
    pub fn data_rows(&self) -> impl Iterator<Item = &ObjectRow> {
        self.rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Data)
    }

    pub fn row(&self, row_id: &str) -> Option<&ObjectRow> {
        self.rows.iter().find(|row| row.row_id == row_id)
    }

    pub fn procedure_effect_current_facts(
        &self,
    ) -> Result<ProcedureEffectCurrentFacts, StoreError> {
        let mut facts = ProcedureEffectCurrentFacts {
            frontier: self.frontier,
            ..ProcedureEffectCurrentFacts::default()
        };
        let mut current_procedures = BTreeMap::<ProcedureId, (RevisionId, u64)>::new();
        let mut current_results = BTreeMap::<ResultEvidenceId, (RevisionId, u64)>::new();
        let mut current_artifacts = BTreeMap::<WorkArtifactId, (RevisionId, u64)>::new();
        for row in self.data_rows() {
            if !matches!(
                row.object_kind.as_deref(),
                Some(
                    "procedure_revision"
                        | "procedure_usage_revision"
                        | "task"
                        | "attempt"
                        | "experiment_run"
                        | "result_evidence"
                        | "work_episode"
                        | "worktree"
                        | "worktree_snapshot"
                        | "work_artifact"
                )
            ) {
                continue;
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            macro_rules! latest {
                ($map:expr, $key:expr, $value:expr) => {{
                    let key = $key;
                    if $map
                        .get(&key)
                        .is_none_or(|(_, seq)| *seq < row.source_event_seq)
                    {
                        $map.insert(key, ($value, row.source_event_seq));
                    }
                }};
            }
            match payload {
                JournalPayload::ProcedureRevisionRecorded(value) => {
                    let value = *value;
                    facts
                        .procedures
                        .insert(value.revision_id, (value.clone(), row.source_event_seq));
                    latest!(current_procedures, value.procedure_id, value.revision_id);
                }
                JournalPayload::ProcedureUsageRecorded(value) => {
                    let value = *value;
                    latest!(facts.usages, value.procedure_usage_id, value);
                }
                JournalPayload::TaskRecorded(value) => {
                    let value = *value;
                    latest!(facts.tasks, value.task_id, value);
                }
                JournalPayload::AttemptRecorded(value) => {
                    let value = *value;
                    latest!(facts.attempts, value.attempt_id, value);
                }
                JournalPayload::ExperimentRunRecorded(value) => {
                    let value = *value;
                    latest!(facts.runs, value.run_id, value);
                }
                JournalPayload::ResultEvidenceRecorded(value) => {
                    let value = *value;
                    facts
                        .results
                        .insert(value.revision_id, (value.clone(), row.source_event_seq));
                    latest!(current_results, value.result_evidence_id, value.revision_id);
                }
                JournalPayload::WorkEpisodeRecorded(value) => {
                    let value = *value;
                    facts
                        .episodes
                        .insert(value.revision_id, (value, row.source_event_seq));
                }
                JournalPayload::WorktreeInstanceRecorded(value) => {
                    let value = *value;
                    latest!(facts.worktrees, value.worktree_instance_id, value);
                }
                JournalPayload::WorktreeSnapshotRecorded(value) => {
                    let value = *value;
                    facts
                        .snapshots
                        .insert(value.worktree_snapshot_id, (value, row.source_event_seq));
                }
                JournalPayload::WorkArtifactRecorded(value) => {
                    let value = *value;
                    facts.artifacts.insert(
                        value.revision.revision_id,
                        (value.clone(), row.source_event_seq),
                    );
                    latest!(
                        current_artifacts,
                        value.work_artifact_id,
                        value.revision.revision_id
                    );
                }
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        facts.current_procedures = current_procedures
            .into_iter()
            .map(|(id, (revision, _))| (id, revision))
            .collect();
        facts.current_results = current_results
            .into_iter()
            .map(|(id, (revision, _))| (id, revision))
            .collect();
        facts.current_artifacts = current_artifacts
            .into_iter()
            .map(|(id, (revision, _))| (id, revision))
            .collect();
        Ok(facts)
    }

    pub fn compile_controlled_procedure_effect(
        &self,
        procedure_revision_id: RevisionId,
    ) -> Result<Vec<evertrace_domain::procedure::ProcedureContextEffectProjection>, StoreError>
    {
        procedure_effect::compile_controlled(self, procedure_revision_id)
    }

    pub fn reconciliation_frontier(
        &self,
        limit: usize,
    ) -> Result<ReconciliationFrontier, StoreError> {
        if limit == 0 {
            return Err(StoreError::InvalidInput);
        }
        let mut candidates = self
            .data_rows()
            .filter(|row| row.row_id.starts_with("runtime:dirty:"))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.source_event_seq
                .cmp(&right.source_event_seq)
                .then_with(|| left.row_id.cmp(&right.row_id))
        });
        let mut items = Vec::new();
        for row in candidates {
            let payload = current_payload(row)?;
            let JournalPayload::DirtyTarget(target) = &payload.payload else {
                return Err(StoreError::StoreCorrupt);
            };
            let target = target.clone();
            if !matches!(
                target.target_kind,
                crate::command::DirtyTargetKind::PhysicalNormalization
                    | crate::command::DirtyTargetKind::CaptureReconciliation
            ) {
                continue;
            }
            if let Some(item) = reconciliation_item(self, payload, target)? {
                items.push(item);
                if items.len() == limit {
                    break;
                }
            }
        }
        Ok(ReconciliationFrontier {
            frontier: self.frontier,
            items,
        })
    }

    pub fn reconciliation_frontier_for_observations(
        &self,
        observation_ids: &[SourceObservationId],
    ) -> Result<ReconciliationFrontier, StoreError> {
        if observation_ids.is_empty()
            || observation_ids.len() > 16
            || observation_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != observation_ids.len()
        {
            return Err(StoreError::InvalidInput);
        }
        let selected = observation_ids
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let mut items = Vec::new();
        for row in self
            .data_rows()
            .filter(|row| row.row_id.starts_with("runtime:dirty:"))
        {
            let payload = current_payload(row)?;
            let JournalPayload::DirtyTarget(target) = &payload.payload else {
                return Err(StoreError::StoreCorrupt);
            };
            let target = target.clone();
            if selected.contains(&target.target_id)
                && matches!(
                    target.target_kind,
                    crate::command::DirtyTargetKind::PhysicalNormalization
                        | crate::command::DirtyTargetKind::CaptureReconciliation
                )
                && let Some(item) = reconciliation_item(self, payload, target)?
            {
                items.push(item);
            }
        }
        items.sort_by(|left, right| {
            left.source_event_seq
                .cmp(&right.source_event_seq)
                .then_with(|| left.row_id.cmp(&right.row_id))
        });
        Ok(ReconciliationFrontier {
            frontier: self.frontier,
            items,
        })
    }

    pub fn reconciliation_artifact_context(
        &self,
        descriptors: &[ReconciliationArtifactDescriptor],
        limit: usize,
    ) -> Result<ReconciliationArtifactFrontier, StoreError> {
        if limit == 0 {
            return Err(StoreError::InvalidInput);
        }
        let mut ordered = descriptors.to_vec();
        ordered.sort();
        ordered.truncate(limit);
        let mut contexts = Vec::with_capacity(ordered.len());
        for descriptor in ordered {
            descriptor.validate()?;
            contexts.push(reconciliation_artifact_item(self, descriptor)?);
        }
        Ok(ReconciliationArtifactFrontier {
            frontier: self.frontier,
            contexts,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkIdentityCurrentView {
    pub frontier: u64,
    pub tasks: BTreeMap<TaskId, Task>,
    pub workstreams: BTreeMap<WorkstreamId, Workstream>,
}

impl WorkIdentityCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        for row in snapshot.data_rows() {
            match row.object_kind.as_deref() {
                Some("task") => {
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::TaskRecorded(task) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    if row.row_id != format!("object:work:task:{}", task.task_id) {
                        return Err(StoreError::StoreCorrupt);
                    }
                    view.tasks.insert(task.task_id, *task);
                }
                Some("workstream") => {
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::WorkstreamRecorded(workstream) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    if row.row_id != format!("object:work:workstream:{}", workstream.workstream_id)
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    view.workstreams
                        .insert(workstream.workstream_id, *workstream);
                }
                _ => {}
            }
        }
        Ok(view)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkBindingCurrentView {
    pub frontier: u64,
    pub bindings: BTreeMap<OperationId, WorkBindingRevision>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttemptCurrentView {
    pub frontier: u64,
    pub attempts: BTreeMap<AttemptId, Attempt>,
    pub competing_groups: BTreeMap<CompetingAttemptGroupId, CompetingAttemptGroup>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkNewAttemptCurrentView {
    pub frontier: u64,
    pub source: Attempt,
    pub existing_child: Option<Attempt>,
}

fn current_attempt_from_lineage(mut revisions: Vec<Attempt>) -> Result<Attempt, StoreError> {
    revisions.sort_by_key(|value| value.revision_generation);
    for (index, revision) in revisions.iter().enumerate() {
        revision.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let generation = u64::try_from(index + 1).map_err(|_| StoreError::StoreCorrupt)?;
        let predecessor = index
            .checked_sub(1)
            .map(|previous| revisions[previous].revision_id);
        if revision.revision_generation != generation
            || revision.predecessor_revision_id != predecessor
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(previous) = index.checked_sub(1) {
            revisions[previous]
                .validate_successor(revision)
                .map_err(|_| StoreError::StoreCorrupt)?;
        }
    }
    revisions.pop().ok_or(StoreError::StoreCorrupt)
}

fn current_group_from_lineage(
    mut revisions: Vec<CompetingAttemptGroup>,
) -> Result<CompetingAttemptGroup, StoreError> {
    revisions.sort_by_key(|value| value.revision_generation);
    for (index, revision) in revisions.iter().enumerate() {
        revision.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let generation = u64::try_from(index + 1).map_err(|_| StoreError::StoreCorrupt)?;
        let predecessor = index
            .checked_sub(1)
            .map(|previous| revisions[previous].revision_id);
        if revision.revision_generation != generation
            || revision.predecessor_revision_id != predecessor
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(previous) = index.checked_sub(1) {
            revisions[previous]
                .validate_successor(revision)
                .map_err(|_| StoreError::StoreCorrupt)?;
        }
    }
    revisions.pop().ok_or(StoreError::StoreCorrupt)
}

impl AttemptCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        let mut attempt_revisions = BTreeMap::<AttemptId, Vec<Attempt>>::new();
        let mut group_revisions =
            BTreeMap::<CompetingAttemptGroupId, Vec<CompetingAttemptGroup>>::new();
        for row in snapshot.data_rows() {
            match row.object_kind.as_deref() {
                Some("attempt") => {
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::AttemptRecorded(value) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    if row.row_id != format!("object:work:attempt:{}", value.revision_id) {
                        return Err(StoreError::StoreCorrupt);
                    }
                    attempt_revisions
                        .entry(value.attempt_id)
                        .or_default()
                        .push(*value);
                }
                Some("competing_attempt_group") => {
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::CompetingAttemptGroupRecorded(value) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    if row.row_id
                        != format!("object:work:competing_attempt_group:{}", value.revision_id)
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    group_revisions
                        .entry(value.competing_group_id)
                        .or_default()
                        .push(*value);
                }
                _ => {}
            }
        }
        for (id, revisions) in attempt_revisions {
            view.attempts
                .insert(id, current_attempt_from_lineage(revisions)?);
        }
        for (id, revisions) in group_revisions {
            view.competing_groups
                .insert(id, current_group_from_lineage(revisions)?);
        }
        Ok(view)
    }

    pub fn for_competing_group(
        snapshot: &ProjectionSnapshot,
        group_id: CompetingAttemptGroupId,
    ) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        let group_ref = group_id.to_string();
        let mut group_revisions = Vec::new();
        for row in snapshot.data_rows().filter(|row| {
            row.object_kind.as_deref() == Some("competing_attempt_group")
                && row.object_id.as_deref() == Some(group_ref.as_str())
        }) {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::CompetingAttemptGroupRecorded(value) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            if value.competing_group_id != group_id
                || row.row_id
                    != format!("object:work:competing_attempt_group:{}", value.revision_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
            group_revisions.push(*value);
        }
        let group = current_group_from_lineage(group_revisions)?;
        let member_ids = group
            .member_attempt_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut attempt_revisions = BTreeMap::<AttemptId, Vec<Attempt>>::new();
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("attempt"))
        {
            let Some(attempt_id) = row
                .object_id
                .as_deref()
                .and_then(|value| value.parse::<AttemptId>().ok())
            else {
                continue;
            };
            if !member_ids.contains(&attempt_id) {
                continue;
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::AttemptRecorded(value) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            if value.attempt_id != attempt_id
                || row.row_id != format!("object:work:attempt:{}", value.revision_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
            attempt_revisions
                .entry(attempt_id)
                .or_default()
                .push(*value);
        }
        for member_id in member_ids {
            let revisions = attempt_revisions
                .remove(&member_id)
                .ok_or(StoreError::StoreCorrupt)?;
            view.attempts
                .insert(member_id, current_attempt_from_lineage(revisions)?);
        }
        view.competing_groups.insert(group_id, group);
        Ok(view)
    }
}

impl MarkNewAttemptCurrentView {
    pub fn for_expected_source(
        snapshot: &ProjectionSnapshot,
        expected_revision_id: RevisionId,
    ) -> Result<Option<Self>, StoreError> {
        let expected_row_id = format!("object:work:attempt:{expected_revision_id}");
        let Some(expected_row) = snapshot
            .data_rows()
            .find(|row| row.row_id == expected_row_id)
        else {
            return Ok(None);
        };
        let payload: JournalPayload = serde_json::from_str(
            expected_row
                .payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        let JournalPayload::AttemptRecorded(expected_attempt) = payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if expected_row.object_kind.as_deref() != Some("attempt")
            || expected_row.object_id.as_deref()
                != Some(expected_attempt.attempt_id.to_string().as_str())
            || expected_attempt.revision_id != expected_revision_id
            || expected_attempt.validate().is_err()
        {
            return Err(StoreError::StoreCorrupt);
        }
        let source_id = expected_attempt.attempt_id;
        let source_ref = source_id.to_string();
        let mut source_revisions = Vec::new();
        let mut child_id: Option<AttemptId> = None;
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("attempt"))
        {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::AttemptRecorded(value) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            if row.row_id != format!("object:work:attempt:{}", value.revision_id) {
                return Err(StoreError::StoreCorrupt);
            }
            if row.object_id.as_deref() == Some(source_ref.as_str()) {
                if value.attempt_id != source_id {
                    return Err(StoreError::StoreCorrupt);
                }
                source_revisions.push(*value);
            } else if value.revision_generation == 1
                && value.predecessor_revision_id.is_none()
                && value.resumes_from_attempt_id == Some(source_id)
            {
                child_id = Some(
                    child_id.map_or(value.attempt_id, |current| current.min(value.attempt_id)),
                );
            }
        }
        let source = current_attempt_from_lineage(source_revisions)?;
        let existing_child = if let Some(child_id) = child_id {
            let child_ref = child_id.to_string();
            let mut revisions = Vec::new();
            for row in snapshot.data_rows().filter(|row| {
                row.object_kind.as_deref() == Some("attempt")
                    && row.object_id.as_deref() == Some(child_ref.as_str())
            }) {
                let payload: JournalPayload = serde_json::from_str(
                    row.payload_json
                        .as_deref()
                        .ok_or(StoreError::StoreCorrupt)?,
                )
                .map_err(|_| StoreError::StoreCorrupt)?;
                let JournalPayload::AttemptRecorded(value) = payload else {
                    return Err(StoreError::StoreCorrupt);
                };
                if value.attempt_id != child_id
                    || row.row_id != format!("object:work:attempt:{}", value.revision_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                revisions.push(*value);
            }
            Some(current_attempt_from_lineage(revisions)?)
        } else {
            None
        };
        Ok(Some(Self {
            frontier: snapshot.frontier,
            source,
            existing_child,
        }))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompetingResolutionEvidenceView {
    pub frontier: u64,
    pub integrations: BTreeMap<IntegrationEventId, IntegrationEvent>,
    pub run_revisions: BTreeMap<RevisionId, ExperimentRun>,
    pub current_results: BTreeMap<ResultEvidenceId, ResultEvidence>,
}

impl CompetingResolutionEvidenceView {
    const MAX_MEMBERS: usize = 64;
    const MAX_FACT_IDS: usize = Self::MAX_MEMBERS * 64;

    pub fn group_id_for_revision(
        snapshot: &ProjectionSnapshot,
        expected_revision_id: RevisionId,
    ) -> Result<Option<CompetingAttemptGroupId>, StoreError> {
        let expected = expected_revision_id.to_string();
        let mut selected = None;
        for row in snapshot.data_rows() {
            if row.object_kind.as_deref() != Some("competing_attempt_group")
                || row.current_revision_id.as_deref() != Some(expected.as_str())
            {
                continue;
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::CompetingAttemptGroupRecorded(value) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            if value.revision_id != expected_revision_id
                || row.object_id.as_deref() != Some(value.competing_group_id.to_string().as_str())
                || row.row_id
                    != format!("object:work:competing_attempt_group:{}", value.revision_id)
                || selected.replace(value.competing_group_id).is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(selected)
    }

    pub fn for_attempts<'a>(
        snapshot: &ProjectionSnapshot,
        attempts: impl IntoIterator<Item = &'a Attempt>,
    ) -> Result<Self, StoreError> {
        let attempts = attempts.into_iter().collect::<Vec<_>>();
        if attempts.len() > Self::MAX_MEMBERS {
            return Err(StoreError::StoreCorrupt);
        }
        let mut integration_ids = BTreeSet::new();
        let mut result_ids = BTreeSet::new();
        for attempt in attempts {
            attempt.validate().map_err(|_| StoreError::StoreCorrupt)?;
            if attempt.integration_event_refs.len() > Self::MAX_MEMBERS
                || attempt.parent_verification_refs.len() > Self::MAX_MEMBERS
            {
                return Err(StoreError::StoreCorrupt);
            }
            integration_ids.extend(attempt.integration_event_refs.iter().copied());
            result_ids.extend(
                attempt
                    .parent_verification_refs
                    .iter()
                    .filter_map(|reference| reference.parse::<ResultEvidenceId>().ok()),
            );
            if integration_ids.len() > Self::MAX_FACT_IDS || result_ids.len() > Self::MAX_FACT_IDS {
                return Err(StoreError::StoreCorrupt);
            }
        }
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        let mut result_revisions = BTreeMap::<RevisionId, (ResultEvidence, u64)>::new();
        for row in snapshot.data_rows() {
            match row.object_kind.as_deref() {
                Some("integration_event") => {
                    let Some(id) = row
                        .object_id
                        .as_deref()
                        .and_then(|value| value.parse::<IntegrationEventId>().ok())
                    else {
                        continue;
                    };
                    if !integration_ids.contains(&id) {
                        continue;
                    }
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::IntegrationEventRecorded(value) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    if value.integration_event_id != id
                        || row.row_id != crate::repository::integration_row_id(&id)
                        || view.integrations.insert(id, *value).is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                Some("result_evidence") => {
                    let Some(id) = row
                        .object_id
                        .as_deref()
                        .and_then(|value| value.parse::<ResultEvidenceId>().ok())
                    else {
                        continue;
                    };
                    if !result_ids.contains(&id) {
                        continue;
                    }
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::ResultEvidenceRecorded(value) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    if value.result_evidence_id != id
                        || row.row_id
                            != format!("object:work:result_evidence:{}", value.revision_id)
                        || row.current_revision_id.as_deref()
                            != Some(value.revision_id.to_string().as_str())
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    if result_revisions.len() >= Self::MAX_FACT_IDS
                        || result_revisions
                            .insert(value.revision_id, (*value, row.source_event_seq))
                            .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                _ => {}
            }
        }
        let mut current_results = BTreeMap::new();
        autoresearch::rebuild_results(&mut current_results, &result_revisions)?;
        view.current_results = current_results
            .into_iter()
            .map(|(id, (value, _))| (id, value))
            .collect();
        let run_revision_ids = view
            .current_results
            .values()
            .map(|result| result.experiment_run_revision_id)
            .collect::<BTreeSet<_>>();
        if run_revision_ids.len() > Self::MAX_FACT_IDS {
            return Err(StoreError::StoreCorrupt);
        }
        let run_revision_refs = run_revision_ids
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        for row in snapshot.data_rows().filter(|row| {
            row.object_kind.as_deref() == Some("experiment_run")
                && row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| run_revision_refs.contains(id))
        }) {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::ExperimentRunRecorded(value) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            value.validate().map_err(|_| StoreError::StoreCorrupt)?;
            if !run_revision_ids.contains(&value.revision_id)
                || row.row_id != format!("object:work:experiment_run:{}", value.revision_id)
                || row.object_id.as_deref() != Some(value.run_id.to_string().as_str())
                || row.current_revision_id.as_deref()
                    != Some(value.revision_id.to_string().as_str())
                || view
                    .run_revisions
                    .insert(value.revision_id, *value)
                    .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(view)
    }
}

fn current_binding_lineage<'a>(
    bindings: impl IntoIterator<Item = &'a WorkBindingRevision>,
) -> Result<BTreeMap<OperationId, &'a WorkBindingRevision>, StoreError> {
    let mut by_operation = BTreeMap::<OperationId, Vec<&WorkBindingRevision>>::new();
    for binding in bindings {
        binding.validate().map_err(|_| StoreError::StoreCorrupt)?;
        by_operation
            .entry(binding.operation_id)
            .or_default()
            .push(binding);
    }
    let mut current = BTreeMap::new();
    for (operation_id, revisions) in &mut by_operation {
        revisions.sort_by_key(|value| value.revision_generation);
        for (index, revision) in revisions.iter().enumerate() {
            let generation = u64::try_from(index + 1).map_err(|_| StoreError::StoreCorrupt)?;
            let predecessor = index
                .checked_sub(1)
                .map(|previous| revisions[previous].work_binding_revision_id);
            if revision.revision_generation != generation
                || revision.predecessor_revision_id != predecessor
            {
                return Err(StoreError::StoreCorrupt);
            }
            if let Some(previous) = index.checked_sub(1) {
                revisions[previous]
                    .validate_successor(revision)
                    .map_err(|_| StoreError::StoreCorrupt)?;
            }
        }
        let latest = revisions.last().copied().ok_or(StoreError::StoreCorrupt)?;
        current.insert(*operation_id, latest);
    }
    Ok(current)
}

impl WorkBindingCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut revisions = Vec::new();
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("work_binding"))
        {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::WorkBindingRecorded(binding) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            let binding = *binding;
            if row.row_id
                != format!(
                    "object:work:work_binding:{}",
                    binding.work_binding_revision_id
                )
            {
                return Err(StoreError::StoreCorrupt);
            }
            binding.validate().map_err(|_| StoreError::StoreCorrupt)?;
            revisions.push(binding);
        }
        let bindings = current_binding_lineage(revisions.iter())?
            .into_iter()
            .map(|(operation_id, binding)| (operation_id, binding.clone()))
            .collect();
        Ok(Self {
            frontier: snapshot.frontier,
            bindings,
        })
    }

    pub fn active_context(&self, operation_id: OperationId) -> Option<ActiveWorkContext> {
        self.bindings
            .get(&operation_id)
            .map(ActiveWorkContext::from_current)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedCurrentDependency {
    pub row_id: String,
    pub source_event_seq: u64,
    pub payload: JournalPayload,
}

#[derive(Default)]
struct DependencyCollector {
    by_row_id: BTreeMap<String, NamedCurrentDependency>,
}

impl DependencyCollector {
    fn insert(&mut self, dependency: NamedCurrentDependency) -> Result<(), StoreError> {
        if self.by_row_id.contains_key(&dependency.row_id) {
            return Ok(());
        }
        if self.by_row_id.len() == MAX_S10_RECONCILIATION_DEPENDENCIES {
            return Err(StoreError::ReconciliationDependencyOverflow);
        }
        self.by_row_id.insert(dependency.row_id.clone(), dependency);
        Ok(())
    }

    fn into_dependencies(self) -> Vec<NamedCurrentDependency> {
        self.by_row_id.into_values().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationWorkItem {
    pub row_id: String,
    pub target_kind: crate::command::DirtyTargetKind,
    pub target_id: String,
    pub source_event_seq: u64,
    pub dependencies: Vec<NamedCurrentDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationFrontier {
    pub frontier: u64,
    pub items: Vec<ReconciliationWorkItem>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReconciliationArtifactKind {
    GapMarker,
    Quarantine,
    Outage,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReconciliationArtifactDescriptor {
    pub kind: ReconciliationArtifactKind,
    pub artifact_id: String,
    pub marker_id: Option<String>,
    pub redacted_fingerprint: Option<String>,
    pub session_ref: Option<String>,
    pub source_ref: Option<String>,
}

impl ReconciliationArtifactDescriptor {
    fn validate(&self) -> Result<(), StoreError> {
        if self.artifact_id.is_empty()
            || self.artifact_id.len() > 512
            || self.redacted_fingerprint.as_ref().is_some_and(|value| {
                value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || self
                .marker_id
                .as_ref()
                .is_some_and(|value| value.is_empty())
            || self
                .session_ref
                .as_ref()
                .is_some_and(|value| value.is_empty())
            || self
                .source_ref
                .as_ref()
                .is_some_and(|value| value.is_empty())
            || self.kind == ReconciliationArtifactKind::Outage
                && (self.marker_id.is_some() || self.redacted_fingerprint.is_some())
        {
            return Err(StoreError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationArtifactOwnership {
    Owned,
    Unowned,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationArtifactContext {
    pub descriptor: ReconciliationArtifactDescriptor,
    pub ownership: ReconciliationArtifactOwnership,
    pub dependencies: Vec<NamedCurrentDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationArtifactFrontier {
    pub frontier: u64,
    pub contexts: Vec<ReconciliationArtifactContext>,
}

fn reconciliation_artifact_item(
    snapshot: &ProjectionSnapshot,
    descriptor: ReconciliationArtifactDescriptor,
) -> Result<ReconciliationArtifactContext, StoreError> {
    let unowned_quarantine = descriptor.kind == ReconciliationArtifactKind::Quarantine
        && (descriptor.session_ref.is_none() || descriptor.source_ref.is_none());
    let mut dependencies = DependencyCollector::default();
    let mut identity = descriptor
        .session_ref
        .clone()
        .zip(descriptor.source_ref.clone());
    let mut conflict = false;
    let mut gap_count = 0usize;
    for row in matching_gap_rows(snapshot, &descriptor)? {
        gap_count += 1;
        if gap_count > 1 {
            conflict = true;
        }
        let dependency = current_payload(row)?;
        let JournalPayload::CaptureGapMarkerRecorded(gap) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if descriptor
            .redacted_fingerprint
            .as_ref()
            .is_some_and(|value| value != &gap.redacted_fingerprint)
            || descriptor
                .session_ref
                .as_ref()
                .is_some_and(|value| value != &gap.session_ref)
            || descriptor
                .source_ref
                .as_ref()
                .is_some_and(|value| value != &gap.source_ref)
        {
            conflict = true;
        } else if !unowned_quarantine {
            identity = Some((gap.session_ref.clone(), gap.source_ref.clone()));
        }
        dependencies.insert(dependency)?;
    }
    if descriptor.kind == ReconciliationArtifactKind::Outage {
        let row_id = format!(
            "object:evidence:capture_outage_interval:{}",
            descriptor.artifact_id
        );
        if let Some(row) = snapshot.row(&row_id) {
            let dependency = current_payload(row)?;
            let JournalPayload::CaptureOutageIntervalRecorded(outage) = &dependency.payload else {
                return Err(StoreError::StoreCorrupt);
            };
            if descriptor
                .session_ref
                .as_ref()
                .is_some_and(|value| value != &outage.session_ref)
                || descriptor
                    .source_ref
                    .as_ref()
                    .is_some_and(|value| value != &outage.source_ref)
            {
                conflict = true;
            } else {
                identity = Some((outage.session_ref.clone(), outage.source_ref.clone()));
            }
            dependencies.insert(dependency)?;
        }
    }
    if unowned_quarantine {
        return Ok(ReconciliationArtifactContext {
            descriptor,
            ownership: if conflict {
                ReconciliationArtifactOwnership::Conflict
            } else {
                ReconciliationArtifactOwnership::Unowned
            },
            dependencies: dependencies.into_dependencies(),
        });
    }
    let Some((session_ref, source_ref)) = identity else {
        return Ok(ReconciliationArtifactContext {
            descriptor,
            ownership: if conflict {
                ReconciliationArtifactOwnership::Conflict
            } else {
                ReconciliationArtifactOwnership::Unowned
            },
            dependencies: dependencies.into_dependencies(),
        });
    };
    collect_artifact_outages(snapshot, &session_ref, &source_ref, &mut dependencies)?;
    let mut affected_cohort = false;
    let needles = [
        json_field_fragment("source_session_ref", &session_ref)?,
        serde_json::to_string(&source_ref).map_err(|_| StoreError::Serialization)?,
    ];
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("source_receipt")
            && row
                .payload_json
                .as_deref()
                .is_some_and(|json| needles.iter().all(|needle| json.contains(needle)))
    }) {
        let dependency = current_payload(row)?;
        let JournalPayload::SourceReceiptRecorded(receipt) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if receipt.source_session_ref != session_ref
            || receipt.source_ref != source_ref
                && source_revision_ref(&receipt.source_instance_id, &receipt.source_revision)
                    != source_ref
        {
            continue;
        }
        let observation_row_id = format!(
            "object:evidence:source_observation:{}",
            receipt.source_observation_id
        );
        if let Some(observation) = snapshot.row(&observation_row_id) {
            dependencies.insert(current_payload(observation)?)?;
        }
        let (_, has_current_lane_receipt) =
            collect_capture_dependencies(snapshot, &dependency, &mut dependencies)?;
        affected_cohort |= has_current_lane_receipt;
        dependencies.insert(dependency)?;
    }
    let ownership = if conflict {
        ReconciliationArtifactOwnership::Conflict
    } else if affected_cohort {
        ReconciliationArtifactOwnership::Owned
    } else {
        ReconciliationArtifactOwnership::Unowned
    };
    Ok(ReconciliationArtifactContext {
        descriptor,
        ownership,
        dependencies: dependencies.into_dependencies(),
    })
}

fn matching_gap_rows<'a>(
    snapshot: &'a ProjectionSnapshot,
    descriptor: &ReconciliationArtifactDescriptor,
) -> Result<Box<dyn Iterator<Item = &'a ObjectRow> + 'a>, StoreError> {
    if let Some(marker_id) = descriptor.marker_id.as_ref().or_else(|| {
        (descriptor.kind == ReconciliationArtifactKind::Quarantine)
            .then_some(&descriptor.artifact_id)
    }) {
        let row_id = format!("object:evidence:capture_gap_marker:{marker_id}");
        return Ok(Box::new(snapshot.row(&row_id).into_iter()));
    }
    let Some(fingerprint) = &descriptor.redacted_fingerprint else {
        return Ok(Box::new(std::iter::empty()));
    };
    let needle = json_field_fragment("redacted_fingerprint", fingerprint)?;
    Ok(Box::new(snapshot.data_rows().filter(move |row| {
        row.object_kind.as_deref() == Some("capture_gap_marker")
            && row
                .payload_json
                .as_deref()
                .is_some_and(|json| json.contains(&needle))
    })))
}

fn collect_artifact_outages(
    snapshot: &ProjectionSnapshot,
    session_ref: &str,
    source_ref: &str,
    dependencies: &mut DependencyCollector,
) -> Result<(), StoreError> {
    let needles = [
        json_field_fragment("session_ref", session_ref)?,
        json_field_fragment("source_ref", source_ref)?,
    ];
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("capture_outage_interval")
            && row
                .payload_json
                .as_deref()
                .is_some_and(|json| needles.iter().all(|needle| json.contains(needle)))
    }) {
        let dependency = current_payload(row)?;
        let JournalPayload::CaptureOutageIntervalRecorded(outage) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if outage.session_ref == session_ref && outage.source_ref == source_ref {
            dependencies.insert(dependency)?;
        }
    }
    Ok(())
}

fn reconciliation_item(
    snapshot: &ProjectionSnapshot,
    dirty_row: NamedCurrentDependency,
    target: DirtyTarget,
) -> Result<Option<ReconciliationWorkItem>, StoreError> {
    let observation_row_id = format!("object:evidence:source_observation:{}", target.target_id);
    let observation = snapshot
        .row(&observation_row_id)
        .ok_or(StoreError::StoreCorrupt)
        .and_then(current_payload)?;
    let JournalPayload::SourceObservationRecorded(observation_value) = &observation.payload else {
        return Err(StoreError::StoreCorrupt);
    };
    let observation_value = observation_value.clone();
    let receipt_row_id = format!(
        "object:evidence:source_receipt:{}",
        observation_value.source_receipt_ref
    );
    let source_receipt = snapshot
        .row(&receipt_row_id)
        .ok_or(StoreError::StoreCorrupt)
        .and_then(current_payload)?;
    let mut dependencies = DependencyCollector::default();
    dependencies.insert(observation)?;
    dependencies.insert(source_receipt.clone())?;
    let active = match target.target_kind {
        crate::command::DirtyTargetKind::PhysicalNormalization => {
            let watermark = format!("runtime:watermark:normalization:{}", target.target_id);
            if snapshot.row(&watermark).is_some() {
                false
            } else {
                collect_normalization_dependencies(
                    snapshot,
                    &observation_value,
                    &mut dependencies,
                )?;
                true
            }
        }
        crate::command::DirtyTargetKind::CaptureReconciliation => {
            collect_capture_dependencies(snapshot, &source_receipt, &mut dependencies)?.0
                < dirty_row.source_event_seq
        }
        _ => false,
    };
    if !active {
        return Ok(None);
    }
    Ok(Some(ReconciliationWorkItem {
        row_id: dirty_row.row_id,
        target_kind: target.target_kind,
        target_id: target.target_id,
        source_event_seq: dirty_row.source_event_seq,
        dependencies: dependencies.into_dependencies(),
    }))
}

fn current_payload(row: &ObjectRow) -> Result<NamedCurrentDependency, StoreError> {
    let payload_json = row
        .payload_json
        .as_deref()
        .ok_or(StoreError::StoreCorrupt)?;
    let payload: JournalPayload =
        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
    payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
    Ok(NamedCurrentDependency {
        row_id: row.row_id.clone(),
        source_event_seq: row.source_event_seq,
        payload,
    })
}

fn collect_normalization_dependencies(
    snapshot: &ProjectionSnapshot,
    selected: &SourceObservation,
    dependencies: &mut DependencyCollector,
) -> Result<(), StoreError> {
    let exact_key = selected.correlation.exact_key();
    let partial_ref = selected
        .correlation
        .partial_correlation_ref
        .as_deref()
        .filter(|value| !value.is_empty());
    let correlation_needles = if let Some(key) = &exact_key {
        vec![
            json_field_fragment("host_instance_id", &key.host_instance_id)?,
            json_field_fragment("host_trace_lineage_id", &key.host_trace_lineage_id)?,
            json_field_fragment("host_lane_key", &key.host_lane_key)?,
            json_field_fragment("native_request_id", &key.native_request_id)?,
            json_field_fragment(
                "physical_execution_ordinal",
                &key.physical_execution_ordinal,
            )?,
        ]
    } else if let Some(reference) = partial_ref {
        vec![json_field_fragment("partial_correlation_ref", reference)?]
    } else {
        Vec::new()
    };
    let mut observation_ids = BTreeSet::from([selected.source_observation_id]);
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("source_observation")
            && !correlation_needles.is_empty()
            && row.payload_json.as_deref().is_some_and(|json| {
                correlation_needles
                    .iter()
                    .all(|needle| json.contains(needle))
            })
    }) {
        let dependency = current_payload(row)?;
        let JournalPayload::SourceObservationRecorded(value) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        let matches = exact_key
            .as_ref()
            .is_some_and(|key| value.correlation.exact_key().as_ref() == Some(key))
            || partial_ref.is_some_and(|reference| {
                value.correlation.partial_correlation_ref.as_deref() == Some(reference)
            });
        if matches {
            observation_ids.insert(value.source_observation_id);
            dependencies.insert(dependency)?;
        }
    }
    collect_observation_relations(snapshot, &observation_ids, dependencies)
}

fn collect_observation_relations(
    snapshot: &ProjectionSnapshot,
    observation_ids: &BTreeSet<SourceObservationId>,
    dependencies: &mut DependencyCollector,
) -> Result<(), StoreError> {
    let observation_needles = observation_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut occurrence_ids = BTreeSet::new();
    for row in rows_referencing(snapshot, "host_occurrence", &observation_needles) {
        let dependency = current_payload(row)?;
        let JournalPayload::HostOccurrenceNormalized(value) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if value
            .source_observation_refs
            .iter()
            .any(|id| observation_ids.contains(id))
        {
            occurrence_ids.insert(value.host_occurrence_id);
            dependencies.insert(dependency)?;
        }
    }
    let occurrence_needles = occurrence_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut operation_ids = BTreeSet::new();
    for row in rows_referencing(snapshot, "operation", &occurrence_needles) {
        let dependency = current_payload(row)?;
        let JournalPayload::OperationDerived(value) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if occurrence_ids.contains(&value.host_occurrence_id) {
            operation_ids.insert(value.operation_id);
            dependencies.insert(dependency)?;
        }
    }
    let operation_needles = operation_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    for row in rows_referencing(snapshot, "scope_effect", &operation_needles) {
        let dependency = current_payload(row)?;
        let JournalPayload::ScopeEffectDerived(value) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if operation_ids.contains(&value.operation_id) {
            dependencies.insert(dependency)?;
        }
    }
    Ok(())
}

fn collect_capture_dependencies(
    snapshot: &ProjectionSnapshot,
    selected_receipt: &NamedCurrentDependency,
    dependencies: &mut DependencyCollector,
) -> Result<(u64, bool), StoreError> {
    let JournalPayload::SourceReceiptRecorded(selected) = &selected_receipt.payload else {
        return Err(StoreError::StoreCorrupt);
    };
    let Some(lifecycle) = selected.lifecycle.as_ref() else {
        return Ok((0, false));
    };
    let incarnation_ref = source_incarnation_ref(selected).ok_or(StoreError::StoreCorrupt)?;
    let mut source_needles = vec![
        json_field_fragment("host_session_id", &lifecycle.host_session_id)?,
        json_field_fragment("agent_id", &lifecycle.agent_id)?,
        json_field_fragment("host_lane_key", &lifecycle.host_lane_key)?,
    ];
    if let Some(value) = lifecycle.incarnation_ref.as_deref() {
        source_needles.push(json_field_fragment("incarnation_ref", value)?);
    }
    let source_rows: Box<dyn Iterator<Item = &ObjectRow>> = if lifecycle.incarnation_ref.is_none() {
        Box::new(std::iter::once(
            snapshot
                .row(&selected_receipt.row_id)
                .ok_or(StoreError::StoreCorrupt)?,
        ))
    } else {
        Box::new(snapshot.data_rows().filter(|row| {
            row.object_kind.as_deref() == Some("source_receipt")
                && row
                    .payload_json
                    .as_deref()
                    .is_some_and(|json| source_needles.iter().all(|needle| json.contains(needle)))
        }))
    };
    let mut cohort_observation_ids = BTreeSet::from([selected.source_observation_id]);
    for row in source_rows {
        let dependency = current_payload(row)?;
        let JournalPayload::SourceReceiptRecorded(value) = &dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if value.lifecycle.as_ref().is_some_and(|candidate| {
            candidate.host_session_id == lifecycle.host_session_id
                && candidate.agent_id == lifecycle.agent_id
                && candidate.host_lane_key == lifecycle.host_lane_key
                && source_incarnation_ref(value).as_ref() == Some(&incarnation_ref)
        }) {
            cohort_observation_ids.insert(value.source_observation_id);
            let observation_row_id = format!(
                "object:evidence:source_observation:{}",
                value.source_observation_id
            );
            if let Some(observation) = snapshot.row(&observation_row_id) {
                dependencies.insert(current_payload(observation)?)?;
            }
            dependencies.insert(dependency)?;
        }
    }
    collect_observation_relations(snapshot, &cohort_observation_ids, dependencies)?;
    let mut import_watermark = 0;
    let mut has_current_lane_receipt = false;
    let lane_needles = [
        json_field_fragment("host_session_id", &lifecycle.host_session_id)?,
        json_field_fragment("agent_id", &lifecycle.agent_id)?,
        json_field_fragment("host_lane_key", &lifecycle.host_lane_key)?,
        json_field_fragment("incarnation_ref", &incarnation_ref)?,
    ];
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("execution_lane")
            && row
                .payload_json
                .as_deref()
                .is_some_and(|json| lane_needles.iter().all(|needle| json.contains(needle)))
    }) {
        let lane_dependency = current_payload(row)?;
        let JournalPayload::ExecutionLaneRecorded(lane) = &lane_dependency.payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if lane.host_session_id != lifecycle.host_session_id
            || lane.agent_id != lifecycle.agent_id
            || lane.host_lane_key != lifecycle.host_lane_key
            || lane.incarnation_ref != incarnation_ref
        {
            continue;
        }
        let receipt_row_id = format!("object:evidence:capture_receipt:{}", lane.execution_lane_id);
        if let Some(row) = snapshot.row(&receipt_row_id) {
            let receipt_dependency = current_payload(row)?;
            let JournalPayload::CaptureReceiptRecorded(receipt) = &receipt_dependency.payload
            else {
                return Err(StoreError::StoreCorrupt);
            };
            import_watermark = import_watermark.max(receipt.import_watermark);
            has_current_lane_receipt = true;
            collect_receipt_references(snapshot, receipt, dependencies)?;
            dependencies.insert(receipt_dependency)?;
        }
        dependencies.insert(lane_dependency)?;
    }
    Ok((import_watermark, has_current_lane_receipt))
}

fn source_incarnation_ref(receipt: &SourceReceipt) -> Option<String> {
    let lifecycle = receipt.lifecycle.as_ref()?;
    Some(lifecycle_incarnation_ref(
        lifecycle,
        receipt.source_observation_id,
    ))
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

fn collect_receipt_references(
    snapshot: &ProjectionSnapshot,
    receipt: &CaptureReceipt,
    dependencies: &mut DependencyCollector,
) -> Result<(), StoreError> {
    let rows = receipt
        .capture_gap_marker_refs
        .iter()
        .map(|reference| format!("object:evidence:capture_gap_marker:{reference}"))
        .chain(
            receipt
                .capture_outage_interval_refs
                .iter()
                .map(|id| format!("object:evidence:capture_outage_interval:{id}")),
        )
        .chain(
            receipt
                .source_close_reconciliation_refs
                .iter()
                .map(|reference| format!("runtime:reconciliation:{reference}")),
        );
    for row_id in rows {
        let row = snapshot.row(&row_id).ok_or(StoreError::StoreCorrupt)?;
        dependencies.insert(current_payload(row)?)?;
    }
    Ok(())
}

fn rows_referencing<'a>(
    snapshot: &'a ProjectionSnapshot,
    object_kind: &'static str,
    needles: &'a [String],
) -> impl Iterator<Item = &'a ObjectRow> {
    snapshot.data_rows().filter(move |row| {
        row.object_kind.as_deref() == Some(object_kind)
            && !needles.is_empty()
            && row
                .payload_json
                .as_deref()
                .is_some_and(|json| needles.iter().any(|needle| json.contains(needle)))
    })
}

fn json_field_fragment<T: serde::Serialize + ?Sized>(
    key: &str,
    value: &T,
) -> Result<String, StoreError> {
    Ok(format!(
        "\"{key}\":{}",
        serde_json::to_string(value).map_err(|_| StoreError::Serialization)?
    ))
}

#[derive(Clone, Default)]
struct ReducerState {
    session_imports: BTreeMap<String, crate::session_import::SessionImportCurrent>,
    migrations: BTreeMap<String, (JournalPayload, u64)>,
    dirty: BTreeMap<String, (DirtyTarget, u64)>,
    outbox: BTreeMap<String, (OutboxEntry, u64)>,
    jobs: BTreeMap<JobId, (DurableJob, u64)>,
    watermarks: BTreeMap<String, (WatermarkAdvanced, u64)>,
    config: Option<(JournalPayload, u64)>,
    stale_audits: BTreeMap<String, (JournalPayload, u64)>,
    source_revisions: BTreeMap<String, (SourceRevisionRecorded, u64)>,
    source_receipts: BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    source_observations: BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    source_watermarks: BTreeMap<String, (SourceIngestWatermark, u64)>,
    evidence_surfaces: BTreeMap<SourceObservationId, (EvidenceSurface, u64)>,
    host_occurrences: BTreeMap<HostOccurrenceId, (HostOccurrence, u64)>,
    host_occurrence_revisions: BTreeMap<(HostOccurrenceId, u32), (HostOccurrence, u64)>,
    operations: BTreeMap<OperationId, (Operation, u64)>,
    operation_revisions: BTreeMap<(OperationId, u32), (Operation, u64)>,
    scope_effects: BTreeMap<ScopeEffectId, (ScopeEffect, u64)>,
    normalization_watermarks: BTreeMap<SourceObservationId, (NormalizationWatermark, u64)>,
    execution_lanes: BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    execution_lane_revisions: BTreeMap<(ExecutionLaneId, u32), (ExecutionLane, u64)>,
    capture_receipts: BTreeMap<ExecutionLaneId, (CaptureReceipt, u64)>,
    capture_receipt_revisions:
        BTreeMap<evertrace_domain::ids::CaptureReceiptId, (CaptureReceipt, u64)>,
    capture_gaps: BTreeMap<String, (CaptureGapMarkerEvidence, u64)>,
    capture_outages: BTreeMap<CaptureOutageIntervalId, (CaptureOutageInterval, u64)>,
    source_close_reconciliations: BTreeMap<String, (SourceCloseReconciliation, u64)>,
    repositories: BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    worktrees: BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    worktree_snapshots: BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    worktree_transitions: BTreeMap<WorktreeTransitionId, (WorktreeTransition, u64)>,
    integration_events: BTreeMap<IntegrationEventId, (IntegrationEvent, u64)>,
    tasks: BTreeMap<TaskId, (Task, u64)>,
    workstreams: BTreeMap<WorkstreamId, (Workstream, u64)>,
    work_bindings: BTreeMap<WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    attempts: BTreeMap<AttemptId, (Attempt, u64)>,
    competing_groups: BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    attempt_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (Attempt, u64)>,
    competing_group_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (CompetingAttemptGroup, u64)>,
    operation_bursts: BTreeMap<OperationBurstId, (OperationBurst, u64)>,
    operation_burst_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (OperationBurst, u64)>,
    episodes: BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    episode_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    checkpoints: BTreeMap<String, (WorkCheckpoint, u64)>,
    corrections: BTreeMap<evertrace_domain::revision::RevisionId, (SegmentationCorrection, u64)>,
    recovery_requests: BTreeMap<RecoveryCaptureRequestId, (RecoveryCaptureRequest, u64)>,
    recovery_request_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (RecoveryCaptureRequest, u64)>,
    recovery_bundles: BTreeMap<RecoveryBundleId, (RecoveryBundle, u64)>,
    recovery_applications: BTreeMap<RecoveryApplicationId, (RecoveryApplication, u64)>,
    recovery_application_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (RecoveryApplication, u64)>,
    experiment_runs: BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    experiment_run_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (ExperimentRun, u64)>,
    result_evidence: BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    result_evidence_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (ResultEvidence, u64)>,
    work_artifacts: BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    artifact_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (WorkArtifact, u64)>,
    atoms: BTreeMap<AtomId, (Atom, u64)>,
    atom_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (Atom, u64)>,
    proposals: BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    proposal_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (RevisionProposal, u64)>,
    recall_ledger: recall_ledger::RecallLedgerState,
    s23: s23::S23State,
    procedure: procedure::ProcedureState,
    synthesis: synthesis::SynthesisState,
}

#[derive(Clone, Debug)]
struct KnownSourceRange {
    sequences: BTreeSet<u64>,
    sequence_origin: Option<u64>,
    close_watermark: Option<u64>,
    eligible_event_manifest_refs: BTreeSet<String>,
}

impl KnownSourceRange {
    fn first_sequence(&self) -> Option<u64> {
        self.sequence_origin
            .or_else(|| self.sequences.first().copied())
    }

    fn last_sequence(&self) -> Option<u64> {
        self.sequences.last().copied()
    }

    fn contiguous_through(&self) -> Option<u64> {
        let first = self.first_sequence()?;
        let mut expected = first;
        for sequence in self.sequences.range(first..) {
            if *sequence != expected {
                break;
            }
            expected = expected.saturating_add(1);
        }
        Some(expected.saturating_sub(1))
    }

    fn covers(&self, first: u64, last: u64) -> bool {
        if first > last {
            return false;
        }
        let mut expected = first;
        for sequence in self.sequences.range(first..=last) {
            if *sequence != expected {
                return false;
            }
            if expected == last {
                return true;
            }
            expected = expected.saturating_add(1);
        }
        false
    }
}

#[derive(Clone, Default)]
pub(crate) struct JournalAdmissionState {
    session_imports: BTreeMap<String, crate::session_import::SessionImportCurrent>,
    frontier: u64,
    source_ranges: BTreeMap<String, KnownSourceRange>,
    source_observations: BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    source_receipts: BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    evidence_surfaces: BTreeMap<SourceObservationId, (EvidenceSurface, u64)>,
    host_occurrences: BTreeMap<HostOccurrenceId, (HostOccurrence, u64)>,
    host_occurrence_revisions: BTreeMap<(HostOccurrenceId, u32), (HostOccurrence, u64)>,
    operations: BTreeMap<OperationId, (Operation, u64)>,
    operation_revisions: BTreeMap<(OperationId, u32), (Operation, u64)>,
    scope_effects: BTreeMap<ScopeEffectId, (ScopeEffect, u64)>,
    execution_lanes: BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    execution_lane_revisions: BTreeMap<(ExecutionLaneId, u32), (ExecutionLane, u64)>,
    capture_receipts: BTreeMap<ExecutionLaneId, (CaptureReceipt, u64)>,
    capture_receipt_revisions:
        BTreeMap<evertrace_domain::ids::CaptureReceiptId, (CaptureReceipt, u64)>,
    capture_gaps: BTreeMap<String, (CaptureGapMarkerEvidence, u64)>,
    capture_outages: BTreeMap<CaptureOutageIntervalId, (CaptureOutageInterval, u64)>,
    source_close_reconciliations: BTreeMap<String, (SourceCloseReconciliation, u64)>,
    repositories: BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    worktrees: BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    worktree_snapshots: BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    worktree_transitions: BTreeMap<WorktreeTransitionId, (WorktreeTransition, u64)>,
    integration_events: BTreeMap<IntegrationEventId, (IntegrationEvent, u64)>,
    tasks: BTreeMap<TaskId, (Task, u64)>,
    workstreams: BTreeMap<WorkstreamId, (Workstream, u64)>,
    work_bindings: BTreeMap<WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    attempts: BTreeMap<AttemptId, (Attempt, u64)>,
    competing_groups: BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    attempt_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (Attempt, u64)>,
    competing_group_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (CompetingAttemptGroup, u64)>,
    operation_bursts: BTreeMap<OperationBurstId, (OperationBurst, u64)>,
    operation_burst_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (OperationBurst, u64)>,
    episodes: BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    episode_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    checkpoints: BTreeMap<String, (WorkCheckpoint, u64)>,
    corrections: BTreeMap<evertrace_domain::revision::RevisionId, (SegmentationCorrection, u64)>,
    recovery_requests: BTreeMap<RecoveryCaptureRequestId, (RecoveryCaptureRequest, u64)>,
    recovery_request_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (RecoveryCaptureRequest, u64)>,
    recovery_bundles: BTreeMap<RecoveryBundleId, (RecoveryBundle, u64)>,
    recovery_applications: BTreeMap<RecoveryApplicationId, (RecoveryApplication, u64)>,
    recovery_application_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (RecoveryApplication, u64)>,
    experiment_runs: BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    experiment_run_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (ExperimentRun, u64)>,
    result_evidence: BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    result_evidence_revisions:
        BTreeMap<evertrace_domain::revision::RevisionId, (ResultEvidence, u64)>,
    work_artifacts: BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    artifact_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (WorkArtifact, u64)>,
    atoms: BTreeMap<AtomId, (Atom, u64)>,
    atom_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (Atom, u64)>,
    proposals: BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    proposal_revisions: BTreeMap<evertrace_domain::revision::RevisionId, (RevisionProposal, u64)>,
    recall_ledger: recall_ledger::RecallLedgerState,
    s23: s23::S23State,
    procedure: procedure::ProcedureState,
    synthesis: synthesis::SynthesisState,
    jobs: BTreeMap<evertrace_domain::ids::JobId, DurableJob>,
}

fn recall_scope_matches(
    scope: &evertrace_domain::semantic::AtomScope,
    episode: &WorkEpisode,
) -> bool {
    match scope {
        evertrace_domain::semantic::AtomScope::Task { task_id } => *task_id == episode.task_id,
        evertrace_domain::semantic::AtomScope::Repository {
            repository_instance_id,
        } => Some(*repository_instance_id) == episode.repository_instance_id,
        evertrace_domain::semantic::AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => {
            Some(*repository_instance_id) == episode.repository_instance_id
                && Some(*worktree_instance_id) == episode.worktree_instance_id
        }
        evertrace_domain::semantic::AtomScope::Global => false,
    }
}

fn select_episode_checkpoints<'a>(
    episode_id: evertrace_domain::ids::WorkEpisodeId,
    episode_generation: u64,
    checkpoint_refs: &[String],
    episode_revisions: &'a BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    checkpoints: &'a BTreeMap<String, (WorkCheckpoint, u64)>,
) -> Result<Option<(&'a WorkCheckpoint, Option<&'a WorkCheckpoint>)>, StoreError> {
    let mut candidates = Vec::with_capacity(checkpoint_refs.len());
    for reference in checkpoint_refs {
        let (checkpoint, source_event_seq) =
            checkpoints.get(reference).ok_or(StoreError::StoreCorrupt)?;
        let (source_episode, _) = episode_revisions
            .get(&checkpoint.episode_revision_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if checkpoint.stable_key() != *reference
            || checkpoint.episode_id != episode_id
            || source_episode.episode_id != episode_id
            || source_episode.revision_generation > episode_generation
        {
            return Err(StoreError::StoreCorrupt);
        }
        candidates.push((checkpoint, *source_event_seq));
    }
    candidates.sort_by_key(|(checkpoint, source_event_seq)| {
        (checkpoint.source_watermark, *source_event_seq)
    });
    if candidates.windows(2).any(|pair| {
        pair[0].0.source_watermark == pair[1].0.source_watermark && pair[0].1 == pair[1].1
    }) {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(candidates.last().map(|(latest, _)| {
        (
            *latest,
            candidates.iter().rev().nth(1).map(|(value, _)| *value),
        )
    }))
}

fn select_recall_binding<'a>(
    bindings: impl Iterator<Item = (&'a WorkBindingRevision, u64)>,
    operation_ids: &[OperationId],
    task_id: TaskId,
    workstream_id: WorkstreamId,
    episode_id: evertrace_domain::ids::WorkEpisodeId,
) -> Result<Option<&'a WorkBindingRevision>, StoreError> {
    let mut selected = None;
    for (candidate, candidate_seq) in bindings.filter(|(binding, _)| {
        operation_ids.contains(&binding.operation_id)
            && binding.assignment_status == AssignmentStatus::Resolved
            && binding.primary_binding.task_id == Some(task_id)
            && binding.primary_binding.workstream_id == Some(workstream_id)
            && binding.primary_binding.episode_id == Some(episode_id)
    }) {
        if let Some((_, selected_seq)) = selected {
            if candidate_seq == selected_seq {
                return Err(StoreError::StoreCorrupt);
            }
            if candidate_seq < selected_seq {
                continue;
            }
        }
        selected = Some((candidate, candidate_seq));
    }
    Ok(selected.map(|(binding, _)| binding))
}

impl JournalAdmissionState {
    fn synthesis_ref_set(&self) -> std::collections::BTreeSet<String> {
        let mut refs = std::collections::BTreeSet::new();
        macro_rules! extend_keys {
            ($values:expr) => {
                refs.extend($values.keys().map(ToString::to_string));
            };
        }
        extend_keys!(self.source_observations);
        extend_keys!(self.source_receipts);
        extend_keys!(self.host_occurrences);
        extend_keys!(self.operations);
        extend_keys!(self.scope_effects);
        extend_keys!(self.capture_receipt_revisions);
        extend_keys!(self.tasks);
        extend_keys!(self.workstreams);
        extend_keys!(self.work_bindings);
        extend_keys!(self.attempts);
        extend_keys!(self.attempt_revisions);
        extend_keys!(self.episodes);
        extend_keys!(self.episode_revisions);
        refs.extend(self.checkpoints.keys().cloned());
        extend_keys!(self.experiment_runs);
        extend_keys!(self.experiment_run_revisions);
        extend_keys!(self.result_evidence);
        extend_keys!(self.result_evidence_revisions);
        extend_keys!(self.work_artifacts);
        extend_keys!(self.artifact_revisions);
        extend_keys!(self.atoms);
        extend_keys!(self.atom_revisions);
        refs.extend(self.procedure.revision_refs().map(ToString::to_string));
        refs
    }

    fn synthesis_proposal_evidence_ref_set(&self) -> std::collections::BTreeSet<String> {
        let mut refs = std::collections::BTreeSet::new();
        refs.extend(self.source_observations.keys().map(ToString::to_string));
        refs.extend(self.source_receipts.keys().map(ToString::to_string));
        refs.extend(self.result_evidence.keys().map(ToString::to_string));
        refs.extend(
            self.result_evidence_revisions
                .keys()
                .map(ToString::to_string),
        );
        refs.extend(self.work_artifacts.keys().map(ToString::to_string));
        refs.extend(self.artifact_revisions.keys().map(ToString::to_string));
        refs.extend(self.atom_revisions.keys().map(ToString::to_string));
        refs
    }

    pub(crate) fn recall_current_contexts(
        &self,
        frontier: u64,
        limit: usize,
    ) -> Result<Vec<RecallCurrentContext>, StoreError> {
        if limit == 0 || limit > 32 {
            return Err(StoreError::InvalidInput);
        }
        let active_operation_ids = self
            .episodes
            .values()
            .filter(|(episode, _)| {
                episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open
            })
            .flat_map(|(episode, _)| {
                episode.execution_lane_ids.iter().filter_map(|lane_id| {
                    self.execution_lanes.get(lane_id).and_then(|(lane, _)| {
                        (lane.status == LaneStatus::Active
                            && episode.session_ids.contains(&lane.host_session_id))
                        .then_some(lane.operation_ids.iter())
                    })
                })
            })
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut current_bindings = BTreeMap::<OperationId, (&WorkBindingRevision, u64)>::new();
        for (binding, source_seq) in self.work_bindings.values() {
            if !active_operation_ids.contains(&binding.operation_id) {
                continue;
            }
            match current_bindings.entry(binding.operation_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((binding, *source_seq));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (current, current_seq) = *entry.get();
                    if current.revision_generation == binding.revision_generation {
                        return Err(StoreError::StoreCorrupt);
                    }
                    if (current.revision_generation, current_seq)
                        < (binding.revision_generation, *source_seq)
                    {
                        entry.insert((binding, *source_seq));
                    }
                }
            }
        }
        let mut contexts = Vec::new();
        for (episode, _) in self.episodes.values().filter(|(episode, _)| {
            episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open
        }) {
            for lane_id in &episode.execution_lane_ids {
                let Some((lane, _)) = self.execution_lanes.get(lane_id).filter(|(lane, _)| {
                    lane.status == LaneStatus::Active
                        && episode.session_ids.contains(&lane.host_session_id)
                }) else {
                    continue;
                };
                let session_id = &lane.host_session_id;
                let Some((task, _)) = self.tasks.get(&episode.task_id).filter(|(task, _)| {
                    task.lifecycle == evertrace_domain::work::TaskLifecycle::Active
                }) else {
                    continue;
                };
                let Some((workstream, _)) =
                    self.workstreams
                        .get(&episode.workstream_id)
                        .filter(|(stream, _)| {
                            stream.status == evertrace_domain::work::WorkstreamStatus::Active
                                && stream.task_id == episode.task_id
                                && stream.execution_lane_ids.contains(lane_id)
                        })
                else {
                    continue;
                };
                let Some((checkpoint, previous_checkpoint)) = select_episode_checkpoints(
                    episode.episode_id,
                    episode.revision_generation,
                    &episode.checkpoint_refs,
                    &self.episode_revisions,
                    &self.checkpoints,
                )?
                else {
                    continue;
                };
                let previous_checkpoint = previous_checkpoint.cloned();
                let Some(binding) = select_recall_binding(
                    current_bindings.values().copied(),
                    &lane.operation_ids,
                    episode.task_id,
                    episode.workstream_id,
                    episode.episode_id,
                )?
                else {
                    continue;
                };
                let mut atoms = self
                    .atoms
                    .values()
                    .filter_map(|(atom, source_event_seq)| {
                        (atom.lifecycle_status
                            == evertrace_domain::semantic::AtomLifecycleStatus::Active
                            && atom.kind.is_normative()
                            && self.s23.atom_support_eligible(atom.revision_id)
                            && recall_scope_matches(&atom.scope, episode))
                        .then_some(RecallCurrentAtom {
                            atom: atom.clone(),
                            source_event_seq: *source_event_seq,
                        })
                    })
                    .collect::<Vec<_>>();
                atoms.sort_by_key(|value| value.atom.revision_id);
                if atoms.len() > 256 {
                    return Err(StoreError::ReconciliationDependencyOverflow);
                }
                let mut needs = self
                    .recall_ledger
                    .values()
                    .filter(|need| {
                        need.session_id == *session_id
                            && need.execution_lane_id == *lane_id
                            && need.episode_revision_id == episode.revision_id
                            && need.obligation_state
                                == evertrace_domain::recall::RecallObligationState::Active
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                needs.sort_by_key(|need| need.recall_need_id);
                if needs.len() > 2 {
                    return Err(StoreError::StoreCorrupt);
                }
                let last_presentation_attempts = needs
                    .iter()
                    .filter_map(|need| {
                        self.recall_ledger
                            .last_presentation_attempt(need.recall_need_id)
                            .map(|attempt| (need.recall_need_id, attempt))
                    })
                    .collect();
                contexts.push(RecallCurrentContext {
                    frontier,
                    task: task.clone(),
                    workstream: workstream.clone(),
                    execution_lane: lane.clone(),
                    episode: episode.clone(),
                    checkpoint: checkpoint.clone(),
                    previous_checkpoint,
                    binding: binding.clone(),
                    atoms,
                    needs,
                    last_presentation_attempts,
                });
                if contexts.len() > limit {
                    return Err(StoreError::ReconciliationDependencyOverflow);
                }
            }
        }
        contexts.sort_by(|left, right| {
            left.execution_lane
                .host_session_id
                .cmp(&right.execution_lane.host_session_id)
                .then(
                    left.execution_lane
                        .execution_lane_id
                        .cmp(&right.execution_lane.execution_lane_id),
                )
        });
        if contexts.windows(2).any(|pair| {
            pair[0].execution_lane.host_session_id == pair[1].execution_lane.host_session_id
                && pair[0].execution_lane.execution_lane_id
                    == pair[1].execution_lane.execution_lane_id
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(contexts)
    }

    pub(crate) fn from_journal_rows(rows: &[JournalRow]) -> Result<Self, StoreError> {
        let mut state = Self::default();
        for batch in ordered_command_batches(rows)? {
            state = state.apply_row_batch(&batch)?;
        }
        Ok(state)
    }

    pub(crate) fn apply_command(
        &self,
        command: &JournalCommand,
        first_seq: u64,
    ) -> Result<Self, StoreError> {
        self.validate_job_command(
            command
                .events()
                .iter()
                .map(|event| (&event.payload, event.occurred_at_us)),
        )
        .map_err(|_| StoreError::InvalidInput)?;
        self.validate_transition_pairs(command.events().iter().map(|event| &event.payload))?;
        self.validate_episode_binding_activation(
            command.events().iter().map(|event| &event.payload),
        )?;
        self.validate_competing_selected_command(
            command
                .events()
                .iter()
                .map(|event| (&event.payload, event.source_kind)),
        )
        .map_err(|_| StoreError::InvalidInput)?;
        self.validate_mark_new_attempt_command(
            command
                .events()
                .iter()
                .map(|event| (&event.payload, event.source_kind)),
        )
        .map_err(|_| StoreError::InvalidInput)?;
        self.validate_procedure_usage_command(command.events().iter().map(|event| &event.payload))
            .map_err(|_| StoreError::InvalidInput)?;
        autoresearch::validate_controlled_command(
            autoresearch::ControlledRunAdmissionView {
                runs: &self.experiment_runs,
                attempts: &self.attempts,
                work_bindings: &self.work_bindings,
                operations: &self.operations,
                snapshots: &self.worktree_snapshots,
                receipts: &self.source_receipts,
                observations: &self.source_observations,
                surfaces: &self.evidence_surfaces,
                artifacts: &self.work_artifacts,
                procedures: &self.procedure,
                tasks: &self.tasks,
                workstreams: &self.workstreams,
                episodes: &self.episodes,
                episode_revisions: &self.episode_revisions,
                worktrees: &self.worktrees,
            },
            command.events().iter().map(|event| &event.payload),
            StoreError::InvalidInput,
        )?;
        let accepted_edits = semantic::validate_command_boundary(
            &self.atoms,
            &self.proposals,
            &self.procedure,
            &self.s23,
            command.events().iter().map(|event| {
                (
                    &event.payload,
                    event.occurred_at_us,
                    event.effective_config_hash,
                )
            }),
            StoreError::InvalidInput,
        )?;
        self.procedure
            .validate_command_cohort(
                &self.tasks,
                &accepted_edits,
                command.events().iter().map(|event| &event.payload),
            )
            .map_err(|_| StoreError::InvalidInput)?;
        let synthesis_refs = self.synthesis_ref_set();
        let proposal_evidence_refs = self.synthesis_proposal_evidence_ref_set();
        self.synthesis
            .validate_command(
                synthesis::SynthesisAdmissionView {
                    episodes: &self.episodes,
                    proposals: &self.proposals,
                    atoms: &self.atoms,
                    procedures: &self.procedure,
                    s23: &self.s23,
                    refs: &synthesis_refs,
                    proposal_evidence_refs: &proposal_evidence_refs,
                },
                command.events().iter().map(|event| &event.payload),
            )
            .map_err(|_| StoreError::InvalidInput)?;
        crate::repository::validate_repository_payloads(
            command.events().iter().map(|event| &event.payload),
        )?;
        let mut next = self.clone();
        for (offset, event) in command.events().iter().enumerate() {
            let seq = first_seq
                .checked_add(u64::try_from(offset).map_err(|_| StoreError::InvalidInput)?)
                .ok_or(StoreError::InvalidInput)?;
            next.apply_payload(event.payload.clone(), seq)
                .map_err(|_| StoreError::InvalidInput)?;
        }
        next.validate_relations()
            .map_err(|_| StoreError::InvalidInput)?;
        Ok(next)
    }

    fn validate_episode_binding_activation<'a>(
        &self,
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let command_open = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::WorkEpisodeRecorded(value)
                    if value.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open =>
                {
                    Some(value.episode_id)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let current =
            current_binding_lineage(self.work_bindings.values().map(|(binding, _)| binding))?;
        for binding in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::WorkBindingRecorded(value) => Some(value.as_ref()),
            _ => None,
        }) {
            let Some(episode_id) = binding.primary_binding.episode_id else {
                continue;
            };
            let first_link = current
                .get(&binding.operation_id)
                .is_none_or(|previous| previous.primary_binding.episode_id.is_none());
            if first_link
                && !command_open.contains(&episode_id)
                && self.episodes.get(&episode_id).is_none_or(|(episode, _)| {
                    episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Open
                })
            {
                return Err(StoreError::InvalidInput);
            }
        }
        Ok(())
    }

    fn apply_row_batch(&self, rows: &[&JournalRow]) -> Result<Self, StoreError> {
        let parsed = rows
            .iter()
            .map(|row| {
                let payload = row.payload()?;
                payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
                Ok((payload, row.seq, row.occurred_at_us))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        self.validate_job_command(
            parsed
                .iter()
                .map(|(payload, _, occurred_at_us)| (payload, *occurred_at_us)),
        )?;
        self.validate_transition_pairs(parsed.iter().map(|(payload, _, _)| payload))
            .map_err(|_| StoreError::StoreCorrupt)?;
        self.validate_episode_binding_activation(parsed.iter().map(|(payload, _, _)| payload))
            .map_err(|_| StoreError::StoreCorrupt)?;
        self.validate_competing_selected_command(
            rows.iter()
                .zip(parsed.iter())
                .map(|(row, (payload, _, _))| (payload, row.source_kind)),
        )?;
        self.validate_mark_new_attempt_command(
            rows.iter()
                .zip(parsed.iter())
                .map(|(row, (payload, _, _))| (payload, row.source_kind)),
        )?;
        self.validate_procedure_usage_command(parsed.iter().map(|(payload, _, _)| payload))?;
        autoresearch::validate_controlled_command(
            autoresearch::ControlledRunAdmissionView {
                runs: &self.experiment_runs,
                attempts: &self.attempts,
                work_bindings: &self.work_bindings,
                operations: &self.operations,
                snapshots: &self.worktree_snapshots,
                receipts: &self.source_receipts,
                observations: &self.source_observations,
                surfaces: &self.evidence_surfaces,
                artifacts: &self.work_artifacts,
                procedures: &self.procedure,
                tasks: &self.tasks,
                workstreams: &self.workstreams,
                episodes: &self.episodes,
                episode_revisions: &self.episode_revisions,
                worktrees: &self.worktrees,
            },
            parsed.iter().map(|(payload, _, _)| payload),
            StoreError::StoreCorrupt,
        )?;
        let accepted_edits = semantic::validate_command_boundary(
            &self.atoms,
            &self.proposals,
            &self.procedure,
            &self.s23,
            rows.iter()
                .zip(parsed.iter())
                .map(|(row, (payload, _, _))| {
                    (payload, row.occurred_at_us, row.effective_config_hash)
                }),
            StoreError::StoreCorrupt,
        )?;
        self.procedure.validate_command_cohort(
            &self.tasks,
            &accepted_edits,
            parsed.iter().map(|(payload, _, _)| payload),
        )?;
        let synthesis_refs = self.synthesis_ref_set();
        let proposal_evidence_refs = self.synthesis_proposal_evidence_ref_set();
        self.synthesis.validate_command(
            synthesis::SynthesisAdmissionView {
                episodes: &self.episodes,
                proposals: &self.proposals,
                atoms: &self.atoms,
                procedures: &self.procedure,
                s23: &self.s23,
                refs: &synthesis_refs,
                proposal_evidence_refs: &proposal_evidence_refs,
            },
            parsed.iter().map(|(payload, _, _)| payload),
        )?;
        crate::repository::validate_repository_payloads(
            parsed.iter().map(|(payload, _, _)| payload),
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        let mut next = self.clone();
        for (payload, seq, _) in parsed {
            next.apply_payload(payload, seq)?;
        }
        next.validate_relations()?;
        Ok(next)
    }

    fn validate_competing_selected_command<'a>(
        &self,
        payloads: impl IntoIterator<Item = (&'a JournalPayload, SourceKind)>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let manual_selected = payloads
            .iter()
            .filter_map(|(payload, source_kind)| match payload {
                JournalPayload::CompetingAttemptGroupRecorded(value)
                    if *source_kind == SourceKind::Manual
                        && value.resolution_status == CompetingResolutionStatus::Selected =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if manual_selected.is_empty() {
            return Ok(());
        }
        if payloads.len() != 1 || manual_selected.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let selected = manual_selected[0];
        let (current, _) = self
            .competing_groups
            .get(&selected.competing_group_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if !matches!(
            current.resolution_status,
            CompetingResolutionStatus::Open | CompetingResolutionStatus::Unresolved
        ) {
            return Err(StoreError::StoreCorrupt);
        }
        current
            .validate_successor(selected)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let chosen = selected
            .selected_attempt_id
            .filter(|chosen| current.member_attempt_ids.contains(chosen))
            .ok_or(StoreError::StoreCorrupt)?;
        let attempt = &self
            .attempts
            .get(&chosen)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let cohort = derive_competing_selected_cohort(
            attempt,
            |id| self.integration_events.get(id).map(|(value, _)| value),
            |id| self.result_evidence.get(id).map(|(value, _)| value),
            |id| {
                self.experiment_run_revisions
                    .get(id)
                    .map(|(value, _)| value)
            },
        )
        .ok_or(StoreError::StoreCorrupt)?;
        if selected.resolution_evidence_refs != competing_selected_resolution_refs(current, &cohort)
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    fn validate_mark_new_attempt_command<'a>(
        &self,
        payloads: impl IntoIterator<Item = (&'a JournalPayload, SourceKind)>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let manual_attempts = payloads
            .iter()
            .filter_map(|(payload, source_kind)| match payload {
                JournalPayload::AttemptRecorded(value) if *source_kind == SourceKind::Manual => {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if manual_attempts.is_empty() {
            return Ok(());
        }
        if payloads.len() != 1 || manual_attempts.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let child = manual_attempts[0];
        let source_revision_id = child
            .resume_event_refs
            .as_slice()
            .first()
            .filter(|_| child.resume_event_refs.len() == 1)
            .and_then(|value| value.parse::<RevisionId>().ok())
            .ok_or(StoreError::StoreCorrupt)?;
        let (source, _) = self
            .attempt_revisions
            .get(&source_revision_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if source.revision_id != source_revision_id
            || child.resumes_from_attempt_id != Some(source.attempt_id)
            || self
                .attempts
                .get(&source.attempt_id)
                .is_none_or(|(current, _)| current != source)
            || source.lifecycle_status != AttemptLifecycleStatus::Active
            || source.execution_status != AttemptExecutionStatus::Interrupted
            || self.attempt_revisions.values().any(|(attempt, _)| {
                attempt.revision_generation == 1
                    && attempt.predecessor_revision_id.is_none()
                    && attempt.resumes_from_attempt_id == Some(source.attempt_id)
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        let expected = canonical_mark_new_attempt_child(source, child, self.frontier)?;
        if child != &expected {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    fn validate_job_command<'a>(
        &self,
        payloads: impl IntoIterator<Item = (&'a JournalPayload, i64)>,
    ) -> Result<(), StoreError> {
        let mut jobs = self.jobs.clone();
        for (payload, occurred_at_us) in payloads {
            match payload {
                JournalPayload::JobState(next) => {
                    if let Some(current) = jobs.get(&next.job_id) {
                        validate_job_successor(current, next, occurred_at_us)?;
                    } else if next.state != JobStatus::Queued {
                        return Err(StoreError::StoreCorrupt);
                    }
                    jobs.insert(next.job_id, next.clone());
                }
                JournalPayload::JobLease(lease) => {
                    let job = jobs
                        .get_mut(&lease.job_id)
                        .ok_or(StoreError::StoreCorrupt)?;
                    if job.target_generation != lease.target_generation
                        || job.state != JobStatus::Queued
                        || job.terminal.is_some()
                        || job.attempt.checked_add(1) != Some(lease.attempt)
                        || lease.lease_until_us <= occurred_at_us
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    job.state = JobStatus::Leased;
                    job.attempt = lease.attempt;
                    job.lease_until_us = Some(lease.lease_until_us);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_transition_pairs<'a>(
        &self,
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
    ) -> Result<(), StoreError> {
        let mut lanes = BTreeMap::new();
        let mut receipts = BTreeMap::new();
        for payload in payloads {
            match payload {
                JournalPayload::ExecutionLaneRecorded(value) => {
                    insert_unique_transition(&mut lanes, value.execution_lane_id, value.as_ref())?;
                }
                JournalPayload::CaptureReceiptRecorded(value) => {
                    insert_unique_transition(
                        &mut receipts,
                        value.execution_lane_id,
                        value.as_ref(),
                    )?;
                }
                _ => {}
            }
        }
        if lanes.keys().copied().collect::<BTreeSet<_>>()
            != receipts.keys().copied().collect::<BTreeSet<_>>()
        {
            return Err(StoreError::InvalidInput);
        }
        for (lane_id, lane) in lanes {
            let receipt = receipts
                .get(&lane_id)
                .copied()
                .ok_or(StoreError::InvalidInput)?;
            if lane.active_capture_receipt_revision_id != receipt.capture_receipt_revision_id
                || receipt.execution_lane_id != lane_id
            {
                return Err(StoreError::InvalidInput);
            }
            match (
                self.execution_lanes.get(&lane_id),
                self.capture_receipts.get(&lane_id),
            ) {
                (None, None) => {
                    if lane.lane_revision != 1
                        || lane.predecessor_revision.is_some()
                        || receipt.predecessor_revision_id.is_some()
                    {
                        return Err(StoreError::InvalidInput);
                    }
                }
                (Some((current_lane, _)), Some((current_receipt, _))) => {
                    if lane.lane_revision != current_lane.lane_revision + 1
                        || lane.predecessor_revision != Some(current_lane.lane_revision)
                        || receipt.capture_receipt_revision_id
                            == current_receipt.capture_receipt_revision_id
                        || receipt.predecessor_revision_id
                            != Some(current_receipt.capture_receipt_revision_id)
                        || lane.host_session_id != current_lane.host_session_id
                        || lane.agent_id != current_lane.agent_id
                        || lane.host_lane_key != current_lane.host_lane_key
                        || current_lane.finalized && !lane.finalized
                    {
                        return Err(StoreError::InvalidInput);
                    }
                }
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        Ok(())
    }

    fn apply_payload(&mut self, payload: JournalPayload, seq: u64) -> Result<(), StoreError> {
        match payload {
            JournalPayload::JobState(value) => {
                self.jobs.insert(value.job_id, value);
            }
            JournalPayload::JobLease(value) => {
                let job = self
                    .jobs
                    .get_mut(&value.job_id)
                    .ok_or(StoreError::StoreCorrupt)?;
                job.state = JobStatus::Leased;
                job.attempt = value.attempt;
                job.lease_until_us = Some(value.lease_until_us);
            }
            JournalPayload::SourceReceiptRecorded(value) => {
                record_known_source(&mut self.source_ranges, &value)?;
                if self
                    .source_receipts
                    .insert(value.source_receipt_id, (*value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::SourceObservationRecorded(value) => {
                if self
                    .source_observations
                    .insert(value.source_observation_id, (*value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::EvidenceSurfaceRecorded(value) => {
                if self
                    .evidence_surfaces
                    .insert(value.source_observation_revision_ref, (*value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::HostOccurrenceNormalized(value) => {
                let value = *value;
                replace_occurrence(&mut self.host_occurrences, value.clone(), seq)?;
                let key = (value.host_occurrence_id, value.normalization_revision);
                match self.host_occurrence_revisions.entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert((value, seq));
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get().0 == value => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
            }
            JournalPayload::OperationDerived(value) => {
                let value = *value;
                replace_operation(&mut self.operations, value.clone(), seq)?;
                let key = (value.operation_id, value.operation_revision);
                match self.operation_revisions.entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert((value, seq));
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get().0 == value => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
            }
            JournalPayload::ScopeEffectDerived(value) => {
                if let Some((current, _)) = self.scope_effects.get(&value.scope_effect_id)
                    && current != value.as_ref()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.scope_effects
                    .insert(value.scope_effect_id, (*value, seq));
            }
            JournalPayload::ExecutionLaneRecorded(value) => {
                let value = *value;
                replace_lane(&mut self.execution_lanes, value.clone(), seq)?;
                if self
                    .execution_lane_revisions
                    .insert((value.execution_lane_id, value.lane_revision), (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::CaptureReceiptRecorded(value) => {
                record_capture_receipt(
                    &mut self.capture_receipts,
                    &mut self.capture_receipt_revisions,
                    *value,
                    seq,
                )?;
            }
            JournalPayload::CaptureGapMarkerRecorded(value) => {
                replace_gap(&mut self.capture_gaps, *value, seq)?;
            }
            JournalPayload::CaptureOutageIntervalRecorded(value) => {
                replace_outage(&mut self.capture_outages, *value, seq)?;
            }
            JournalPayload::SourceCloseReconciliation(value) => {
                if self
                    .source_close_reconciliations
                    .insert(value.reconciliation_ref.clone(), (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::RepositoryInstanceRecorded(value) => {
                crate::repository::replace_repository(&mut self.repositories, *value, seq)?;
            }
            JournalPayload::WorktreeInstanceRecorded(value) => {
                crate::repository::replace_worktree(&mut self.worktrees, *value, seq)?;
            }
            JournalPayload::WorktreeSnapshotRecorded(value) => {
                crate::repository::replace_snapshot(&mut self.worktree_snapshots, *value, seq)?;
            }
            JournalPayload::WorktreeTransitionRecorded(value) => {
                crate::repository::replace_transition(&mut self.worktree_transitions, *value, seq)?;
            }
            JournalPayload::IntegrationEventRecorded(value) => {
                crate::repository::replace_integration(&mut self.integration_events, *value, seq)?;
            }
            JournalPayload::TaskRecorded(value) => {
                replace_task(&mut self.tasks, *value, seq)?;
            }
            JournalPayload::WorkstreamRecorded(value) => {
                replace_workstream(&mut self.workstreams, *value, seq)?;
            }
            JournalPayload::WorkBindingRecorded(value) => {
                replace_work_binding(&mut self.work_bindings, *value, seq)?;
            }
            JournalPayload::AttemptRecorded(value) => {
                record_attempt(&mut self.attempts, &mut self.attempt_revisions, *value, seq)?
            }
            JournalPayload::CompetingAttemptGroupRecorded(value) => record_competing_group(
                &mut self.competing_groups,
                &mut self.competing_group_revisions,
                *value,
                seq,
            )?,
            JournalPayload::OperationBurstRecorded(value) => record_operation_burst(
                &mut self.operation_bursts,
                &mut self.operation_burst_revisions,
                *value,
                seq,
            )?,
            JournalPayload::WorkEpisodeRecorded(value) => {
                record_episode(&mut self.episodes, &mut self.episode_revisions, *value, seq)?
            }
            JournalPayload::WorkCheckpointRecorded(value) => {
                record_checkpoint(&mut self.checkpoints, *value, seq)?;
            }
            JournalPayload::SegmentationCorrectionRecorded(value) => {
                record_correction(&mut self.corrections, *value, seq)?;
            }
            JournalPayload::RecoveryCaptureRequestRecorded(value) => recovery::record_request(
                &mut self.recovery_requests,
                &mut self.recovery_request_revisions,
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::RecoveryBundleRecorded(value) => recovery::record_bundle(
                &mut self.recovery_bundles,
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::RecoveryApplicationRecorded(value) => recovery::record_application(
                &mut self.recovery_applications,
                &mut self.recovery_application_revisions,
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::ExperimentRunRecorded(value) => record_run(
                &mut self.experiment_runs,
                Some(&mut self.experiment_run_revisions),
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::ResultEvidenceRecorded(value) => record_result(
                &mut self.result_evidence,
                Some(&mut self.result_evidence_revisions),
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::WorkArtifactRecorded(value) => record_artifact(
                &mut self.work_artifacts,
                Some(&mut self.artifact_revisions),
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::AtomRecorded(value) => semantic::record_atom(
                &mut self.atoms,
                &mut self.atom_revisions,
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            JournalPayload::RevisionProposalRecorded(value) => semantic::record_proposal(
                &mut self.proposals,
                &mut self.proposal_revisions,
                *value,
                seq,
                StoreError::StoreCorrupt,
            )?,
            payload @ (JournalPayload::ProcedureRevisionRecorded(_)
            | JournalPayload::ProcedureStateRecorded(_)
            | JournalPayload::ProcedureUsageRecorded(_)
            | JournalPayload::ProcedureNegativeEvidenceRecorded(_)
            | JournalPayload::ProcedureNegativeReviewRecorded(_)) => {
                self.procedure.apply(payload, seq)?;
            }
            payload @ (JournalPayload::ScenarioRecorded(_)
            | JournalPayload::CoreMembershipRecorded(_)
            | JournalPayload::GlobalSupportContractRecorded(_)
            | JournalPayload::GlobalSupportValidationRecorded(_)) => {
                self.s23.apply(payload, seq)?;
            }
            payload @ (JournalPayload::SemanticDigestRecorded(_)
            | JournalPayload::SemanticDerivationRunRecorded(_)) => {
                self.synthesis.apply(payload, seq)?;
            }
            JournalPayload::RecallLedgerRecorded(value) => {
                self.recall_ledger.apply(*value, seq)?;
            }
            JournalPayload::SessionImportEventRecorded(value) => {
                let next = crate::session_import::apply_session_event(
                    self.session_imports.get(&value.session_id),
                    &value,
                    seq,
                )
                .map_err(|_| StoreError::InvalidInput)?;
                self.session_imports.insert(value.session_id.clone(), next);
            }
            _ => {}
        }
        self.frontier = self.frontier.max(seq);
        Ok(())
    }

    fn validate_relations(&self) -> Result<(), StoreError> {
        validate_capture_relations(
            &self.execution_lanes,
            &self.capture_receipts,
            &self.capture_gaps,
            &self.capture_outages,
            &self.source_close_reconciliations,
            &self.source_ranges,
            &self.operations.keys().copied().collect(),
        )?;
        crate::repository::validate_repository_relations(
            &self.repositories,
            &self.worktrees,
            &self.worktree_snapshots,
            &self.worktree_transitions,
            &self.integration_events,
        )?;
        validate_work_identity_relations(
            &self.tasks,
            &self.workstreams,
            &self.repositories,
            &self.worktrees,
        )?;
        validate_work_binding_relations(
            &self.work_bindings,
            &self.operations,
            &self.scope_effects,
            &self.tasks,
            &self.workstreams,
            &self.attempts,
            &self.competing_groups,
            &self.episodes,
            &self.experiment_runs,
        )?;
        validate_attempt_relations(
            &self.attempts,
            &self.attempt_revisions,
            &self.competing_groups,
            &self.tasks,
            &self.workstreams,
            &self.execution_lanes,
            &self.worktree_snapshots,
            &self.worktree_transitions,
            &self.integration_events,
            &self.work_bindings,
        )?;
        validate_episode_relations(
            &self.episodes,
            &self.episode_revisions,
            &self.checkpoints,
            &self.corrections,
            &self.tasks,
            &self.workstreams,
            &self.attempts,
            &self.attempt_revisions,
            &self.competing_groups,
            &self.work_bindings,
            &self.operation_bursts,
            &self.operation_revisions,
            &self.host_occurrences,
            &self.source_observations,
            &self.scope_effects,
            &self.execution_lanes,
            &self.capture_receipt_revisions,
            &self.capture_gaps,
            &self.capture_outages,
            &self.worktree_snapshots,
            &self.worktree_transitions,
            &self.integration_events,
        )?;
        recovery::validate_relations(recovery::RecoveryRelationInputs {
            requests: &self.recovery_requests,
            bundles: &self.recovery_bundles,
            applications: &self.recovery_applications,
            application_revisions: &self.recovery_application_revisions,
            worktrees: &self.worktrees,
            snapshots: &self.worktree_snapshots,
            operation_revisions: &self.operation_revisions,
            execution_lane_revisions: &self.execution_lane_revisions,
            capture_receipt_revisions: &self.capture_receipt_revisions,
            scope_effects: &self.scope_effects,
            source_observations: &self.source_observations,
            source_receipts: &self.source_receipts,
            attempt_revisions: &self.attempt_revisions,
            competing_group_revisions: &self.competing_group_revisions,
        })?;
        autoresearch::validate_relations(autoresearch::AutoresearchRelationInputs {
            runs: &self.experiment_runs,
            run_revisions: &self.experiment_run_revisions,
            results: &self.result_evidence,
            artifacts: &self.work_artifacts,
            attempts: &self.attempts,
            tasks: &self.tasks,
            workstreams: &self.workstreams,
            operations: &self.operations,
            episodes: &self.episodes,
            snapshots: &self.worktree_snapshots,
            repositories: &self.repositories,
            worktrees: &self.worktrees,
            source_receipts: &self.source_receipts,
            source_observations: &self.source_observations,
        })?;
        semantic::validate_relations(semantic::SemanticRelationInputs {
            atom_revisions: &self.atom_revisions,
            proposal_revisions: &self.proposal_revisions,
            source_observations: &self.source_observations,
            source_receipts: &self.source_receipts,
            tasks: &self.tasks,
            repositories: &self.repositories,
            worktrees: &self.worktrees,
            results: &self.result_evidence,
            artifacts: &self.work_artifacts,
            procedure: &self.procedure,
            s23: &self.s23,
            semantic_digests: self.synthesis.digests(),
        })?;
        self.validate_procedure_relations()?;
        validate_recall_relations(
            self.recall_ledger.values(),
            &self.execution_lanes,
            &self.tasks,
            &self.workstreams,
            &self.episode_revisions,
            &self.atom_revisions,
        )?;
        Ok(())
    }
}

fn validate_recall_ledger_relations(state: &ReducerState) -> Result<(), StoreError> {
    validate_recall_relations(
        state.recall_ledger.values(),
        &state.execution_lanes,
        &state.tasks,
        &state.workstreams,
        &state.episode_revisions,
        &state.atom_revisions,
    )
}

fn validate_recall_relations<'a>(
    needs: impl Iterator<Item = &'a evertrace_domain::recall::RecallNeed>,
    execution_lanes: &BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    tasks: &BTreeMap<TaskId, (Task, u64)>,
    workstreams: &BTreeMap<WorkstreamId, (Workstream, u64)>,
    episode_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    atom_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (Atom, u64)>,
) -> Result<(), StoreError> {
    for need in needs {
        let lane = execution_lanes
            .get(&need.execution_lane_id)
            .ok_or(StoreError::StoreCorrupt)?;
        tasks.get(&need.task_id).ok_or(StoreError::StoreCorrupt)?;
        let workstream = workstreams
            .get(&need.workstream_id)
            .ok_or(StoreError::StoreCorrupt)?;
        let episode = episode_revisions
            .get(&need.episode_revision_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if lane.0.host_session_id != need.session_id
            || workstream.0.task_id != need.task_id
            || !workstream
                .0
                .execution_lane_ids
                .contains(&need.execution_lane_id)
            || episode.0.task_id != need.task_id
            || episode.0.workstream_id != need.workstream_id
            || !episode
                .0
                .execution_lane_ids
                .contains(&need.execution_lane_id)
            || !episode.0.session_ids.contains(&need.session_id)
            || need.source_revision_ids.iter().any(|revision| {
                !atom_revisions.contains_key(revision) && !episode_revisions.contains_key(revision)
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(())
}

fn ordered_command_batches(rows: &[JournalRow]) -> Result<Vec<Vec<&JournalRow>>, StoreError> {
    validate_journal_rows(rows)?;
    let mut by_command = BTreeMap::new();
    for row in rows {
        by_command
            .entry(row.command_id)
            .or_insert_with(Vec::new)
            .push(row);
    }
    let mut batches = by_command
        .into_values()
        .map(|mut batch| {
            batch.sort_by_key(|row| row.ordinal);
            let first_seq = batch
                .first()
                .map(|row| row.seq)
                .ok_or(StoreError::StoreCorrupt)?;
            if batch
                .iter()
                .enumerate()
                .any(|(ordinal, row)| row.seq != first_seq.saturating_add(ordinal as u64))
            {
                return Err(StoreError::StoreCorrupt);
            }
            Ok((first_seq, batch))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    batches.sort_by_key(|(first_seq, _)| *first_seq);
    Ok(batches.into_iter().map(|(_, batch)| batch).collect())
}

fn insert_unique_transition<K: Ord, V>(
    values: &mut BTreeMap<K, V>,
    key: K,
    value: V,
) -> Result<(), StoreError> {
    if values.insert(key, value).is_some() {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn record_known_source(
    ranges: &mut BTreeMap<String, KnownSourceRange>,
    receipt: &SourceReceipt,
) -> Result<(), StoreError> {
    let source_ref = source_revision_ref(&receipt.source_instance_id, &receipt.source_revision);
    let entry = ranges
        .entry(source_ref)
        .or_insert_with(|| KnownSourceRange {
            sequences: BTreeSet::new(),
            sequence_origin: receipt.source_sequence_origin,
            close_watermark: receipt.close_watermark,
            eligible_event_manifest_refs: BTreeSet::new(),
        });
    entry.sequences.insert(receipt.source_sequence);
    if let Some(origin) = receipt.source_sequence_origin {
        if entry
            .sequence_origin
            .is_some_and(|current| current != origin)
        {
            return Err(StoreError::StoreCorrupt);
        }
        entry.sequence_origin = Some(origin);
    }
    entry
        .eligible_event_manifest_refs
        .insert(receipt.eligible_event_manifest_ref.clone());
    if let Some(close) = receipt.close_watermark {
        if entry.last_sequence().is_some_and(|last| close < last)
            || entry
                .close_watermark
                .is_some_and(|current| current != close)
        {
            return Err(StoreError::StoreCorrupt);
        }
        entry.close_watermark = Some(close);
    }
    if entry
        .close_watermark
        .is_some_and(|close| entry.last_sequence().is_some_and(|last| last > close))
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn current_source_ranges(
    receipts: &BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
) -> Result<BTreeMap<String, KnownSourceRange>, StoreError> {
    let mut ranges = BTreeMap::new();
    for (receipt, _) in receipts.values() {
        record_known_source(&mut ranges, receipt)?;
    }
    Ok(ranges)
}

fn validate_capture_relations(
    lanes: &BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    receipts: &BTreeMap<ExecutionLaneId, (CaptureReceipt, u64)>,
    gaps: &BTreeMap<String, (CaptureGapMarkerEvidence, u64)>,
    outages: &BTreeMap<CaptureOutageIntervalId, (CaptureOutageInterval, u64)>,
    reconciliations: &BTreeMap<String, (SourceCloseReconciliation, u64)>,
    source_ranges: &BTreeMap<String, KnownSourceRange>,
    operation_ids: &BTreeSet<OperationId>,
) -> Result<(), StoreError> {
    if lanes.len() != receipts.len() {
        return Err(StoreError::StoreCorrupt);
    }
    let known_close_refs = source_ranges
        .iter()
        .filter_map(|(source_ref, range)| {
            range
                .close_watermark
                .map(|close| format!("{source_ref}:{close}"))
        })
        .collect::<BTreeSet<_>>();
    for (lane_id, (lane, _)) in lanes {
        let receipt = receipts.get(lane_id).ok_or(StoreError::StoreCorrupt)?;
        if receipt.0.capture_receipt_revision_id != lane.active_capture_receipt_revision_id
            || receipt.0.execution_lane_id != *lane_id
            || receipt.0.predecessor_revision_id == Some(receipt.0.capture_receipt_revision_id)
            || lane
                .operation_ids
                .iter()
                .any(|id| !operation_ids.contains(id))
            || receipt
                .0
                .source_revision_refs
                .iter()
                .any(|reference| !source_ranges.contains_key(reference))
            || receipt
                .0
                .source_close_watermark_refs
                .iter()
                .any(|reference| !known_close_refs.contains(reference))
            || receipt
                .0
                .capture_gap_marker_refs
                .iter()
                .any(|reference| !gaps.contains_key(reference))
            || receipt
                .0
                .capture_outage_interval_refs
                .iter()
                .any(|id| !outages.contains_key(id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(parent_id) = lane.parent_lane_id {
            let parent = lanes.get(&parent_id).ok_or(StoreError::StoreCorrupt)?;
            if parent.0.host_session_id != lane.host_session_id || parent_id == *lane_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for reference in &receipt.0.source_close_reconciliation_refs {
            let reconciliation = reconciliations
                .get(reference)
                .ok_or(StoreError::StoreCorrupt)?;
            if reconciliation.0.execution_lane_id != *lane_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if receipt.0.source_coverage == SourceCoverage::Complete
            && !receipt
                .0
                .source_close_reconciliation_refs
                .iter()
                .any(|reference| {
                    reconciliations.get(reference).is_some_and(|(proof, _)| {
                        proof_matches_complete_refs(
                            proof,
                            &receipt.0.source_revision_refs,
                            &receipt.0.source_close_watermark_refs,
                            &receipt.0.eligible_event_manifest_refs,
                        )
                    })
                })
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for reconciliation in reconciliations.values().map(|(value, _)| value) {
        reconciliation
            .validate()
            .map_err(|_| StoreError::StoreCorrupt)?;
        if !lanes.contains_key(&reconciliation.execution_lane_id)
            || reconciliation
                .unresolved_gap_refs
                .iter()
                .any(|reference| !gaps.contains_key(reference))
            || reconciliation
                .unresolved_outage_interval_refs
                .iter()
                .any(|id| !outages.contains_key(id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        for source in &reconciliation.sources {
            let known = source_ranges
                .get(&source.source_revision_ref())
                .ok_or(StoreError::StoreCorrupt)?;
            validate_reconciliation_source(source, known)?;
            if let Some(independent) = &source.independent_reconciliation {
                let independent_ref = source_revision_ref(
                    &independent.source_instance_id,
                    &independent.source_revision,
                );
                let known_independent = source_ranges
                    .get(&independent_ref)
                    .ok_or(StoreError::StoreCorrupt)?;
                if !known_independent.covers(independent.first_sequence, independent.last_sequence)
                    || known_independent.close_watermark != Some(independent.last_sequence)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
    }
    Ok(())
}

fn validate_reconciliation_source(
    source: &crate::command::SourceCloseRange,
    known: &KnownSourceRange,
) -> Result<(), StoreError> {
    if known.first_sequence() != Some(source.first_sequence)
        || known
            .contiguous_through()
            .is_none_or(|frontier| frontier < source.observed_through_sequence)
        || known.close_watermark != Some(source.close_watermark)
        || known.eligible_event_manifest_refs
            != source
                .eligible_event_manifest_refs
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn proof_matches_complete_refs(
    proof: &SourceCloseReconciliation,
    source_revision_refs: &[String],
    source_close_watermark_refs: &[String],
    eligible_event_manifest_refs: &[String],
) -> bool {
    if proof.decision() != SourceCloseDecision::Passed {
        return false;
    }
    let proof_source_refs = proof
        .source_revision_refs()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let receipt_source_refs = source_revision_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let proof_close_refs = proof
        .close_watermark_refs()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let receipt_close_refs = source_close_watermark_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let proof_manifest_refs = proof
        .sources
        .iter()
        .flat_map(|source| source.eligible_event_manifest_refs.iter().cloned())
        .collect::<BTreeSet<_>>();
    let receipt_manifest_refs = eligible_event_manifest_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    proof_source_refs == receipt_source_refs
        && proof_close_refs == receipt_close_refs
        && proof_manifest_refs == receipt_manifest_refs
}

pub fn reduce_journal(rows: &[JournalRow]) -> Result<ProjectionSnapshot, StoreError> {
    let batches = ordered_command_batches(rows)?;
    let mut state = ReducerState::default();
    let mut admission = JournalAdmissionState::default();
    let mut frontier = 0;
    for batch in batches {
        admission = admission.apply_row_batch(&batch)?;
        for row in &batch {
            apply_event(&mut state, row, &batch)?;
            frontier = frontier.max(row.seq);
        }
        state.rebuild_revision_currents()?;
        state.validate_evidence_relations()?;
    }
    state.into_snapshot(frontier)
}

fn apply_event(
    state: &mut ReducerState,
    row: &JournalRow,
    command: &[&JournalRow],
) -> Result<(), StoreError> {
    let payload = row.payload()?;
    payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
    match payload {
        JournalPayload::MigrationApplied(value) => {
            state.migrations.insert(
                value.migration_id.clone(),
                (JournalPayload::MigrationApplied(value), row.seq),
            );
        }
        JournalPayload::DirtyTarget(value) => {
            state.dirty.insert(value.stable_key(), (value, row.seq));
        }
        JournalPayload::OutboxEnqueued(value) => {
            if let Some((existing, _)) = state.outbox.get(&value.outbox_id)
                && existing != &value
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .outbox
                .insert(value.outbox_id.clone(), (value, row.seq));
        }
        JournalPayload::JobState(value) => {
            if let Some((current, _)) = state.jobs.get(&value.job_id) {
                validate_job_successor(current, &value, row.occurred_at_us)?;
            } else if value.state != JobStatus::Queued {
                return Err(StoreError::StoreCorrupt);
            }
            state.jobs.insert(value.job_id, (value, row.seq));
        }
        JournalPayload::JobLease(value) => {
            let (job, source_seq) = state
                .jobs
                .get_mut(&value.job_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if job.target_generation != value.target_generation
                || job.state != JobStatus::Queued
                || job.terminal.is_some()
                || job.attempt.checked_add(1) != Some(value.attempt)
                || value.lease_until_us <= row.occurred_at_us
            {
                return Err(StoreError::StoreCorrupt);
            }
            job.state = JobStatus::Leased;
            job.attempt = value.attempt;
            job.lease_until_us = Some(value.lease_until_us);
            *source_seq = row.seq;
        }
        JournalPayload::WatermarkAdvanced(value) => {
            let key = value.kind.as_str().to_owned();
            if state
                .watermarks
                .get(&key)
                .is_some_and(|(current, _)| value.value < current.value)
            {
                return Err(StoreError::StoreCorrupt);
            }
            state.watermarks.insert(key, (value, row.seq));
        }
        JournalPayload::ConfigAudit(value) => {
            state.config = Some((JournalPayload::ConfigAudit(value), row.seq));
        }
        JournalPayload::StaleGenerationAudit(value) => {
            state.stale_audits.insert(
                row.event_id.clone(),
                (JournalPayload::StaleGenerationAudit(value), row.seq),
            );
        }
        JournalPayload::SourceRevisionRecorded(value) => {
            let key = source_revision_key(&value);
            if let Some((existing, _)) = state.source_revisions.get(&key) {
                if existing != &value {
                    return Err(StoreError::StoreCorrupt);
                }
            } else {
                state.source_revisions.insert(key, (value, row.seq));
            }
        }
        JournalPayload::SourceReceiptRecorded(value) => {
            let value = *value;
            if state
                .source_receipts
                .insert(value.source_receipt_id, (value, row.seq))
                .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::SourceObservationRecorded(value) => {
            let value = *value;
            let receipt = state
                .source_receipts
                .get(&value.source_receipt_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            if receipt.0.source_observation_id != value.source_observation_id
                || receipt.0.source_instance_id != value.source_instance_id
                || receipt.0.source_revision != value.source_revision
                || receipt.0.source_record_identity != value.source_record_identity
            {
                return Err(StoreError::StoreCorrupt);
            }
            if state
                .source_observations
                .insert(value.source_observation_id, (value, row.seq))
                .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::SourceIngestWatermark(value) => {
            validate_source_ingest_watermark(state, &value, command)?;
            let key = value.stable_key();
            if state
                .source_watermarks
                .get(&key)
                .is_none_or(|(current, _)| value.source_sequence >= current.source_sequence)
            {
                state.source_watermarks.insert(key, (value, row.seq));
            }
        }
        JournalPayload::EvidenceSurfaceRecorded(value) => {
            let value = *value;
            if !state
                .source_observations
                .contains_key(&value.source_observation_revision_ref)
                || state
                    .evidence_surfaces
                    .insert(value.source_observation_revision_ref, (value, row.seq))
                    .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::HostOccurrenceNormalized(value) => {
            let value = *value;
            replace_occurrence(&mut state.host_occurrences, value.clone(), row.seq)?;
            let key = (value.host_occurrence_id, value.normalization_revision);
            match state.host_occurrence_revisions.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((value, row.seq));
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get().0 == value => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        JournalPayload::OperationDerived(value) => {
            let value = *value;
            replace_operation(&mut state.operations, value.clone(), row.seq)?;
            let key = (value.operation_id, value.operation_revision);
            match state.operation_revisions.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((value, row.seq));
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get().0 == value => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        JournalPayload::ScopeEffectDerived(value) => {
            let value = *value;
            if let Some((existing, _)) = state.scope_effects.get(&value.scope_effect_id)
                && existing != &value
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .scope_effects
                .insert(value.scope_effect_id, (value, row.seq));
        }
        JournalPayload::NormalizationWatermark(value) => {
            if !state
                .source_observations
                .contains_key(&value.source_observation_id)
                || state
                    .normalization_watermarks
                    .get(&value.source_observation_id)
                    .is_some_and(|(current, _)| current.resolver_version != value.resolver_version)
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .normalization_watermarks
                .insert(value.source_observation_id, (value, row.seq));
        }
        JournalPayload::ExecutionLaneRecorded(value) => {
            let value = *value;
            replace_lane(&mut state.execution_lanes, value.clone(), row.seq)?;
            if state
                .execution_lane_revisions
                .insert(
                    (value.execution_lane_id, value.lane_revision),
                    (value, row.seq),
                )
                .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::CaptureReceiptRecorded(value) => {
            record_capture_receipt(
                &mut state.capture_receipts,
                &mut state.capture_receipt_revisions,
                *value,
                row.seq,
            )?;
        }
        JournalPayload::CaptureGapMarkerRecorded(value) => {
            replace_gap(&mut state.capture_gaps, *value, row.seq)?;
        }
        JournalPayload::CaptureOutageIntervalRecorded(value) => {
            replace_outage(&mut state.capture_outages, *value, row.seq)?;
        }
        JournalPayload::SourceCloseReconciliation(value) => {
            if state
                .source_close_reconciliations
                .contains_key(&value.reconciliation_ref)
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .source_close_reconciliations
                .insert(value.reconciliation_ref.clone(), (value, row.seq));
        }
        JournalPayload::RepositoryInstanceRecorded(value) => {
            crate::repository::replace_repository(&mut state.repositories, *value, row.seq)?;
        }
        JournalPayload::WorktreeInstanceRecorded(value) => {
            crate::repository::replace_worktree(&mut state.worktrees, *value, row.seq)?;
        }
        JournalPayload::WorktreeSnapshotRecorded(value) => {
            crate::repository::replace_snapshot(&mut state.worktree_snapshots, *value, row.seq)?;
        }
        JournalPayload::WorktreeTransitionRecorded(value) => {
            crate::repository::replace_transition(
                &mut state.worktree_transitions,
                *value,
                row.seq,
            )?;
        }
        JournalPayload::IntegrationEventRecorded(value) => {
            crate::repository::replace_integration(&mut state.integration_events, *value, row.seq)?;
        }
        JournalPayload::TaskRecorded(value) => {
            replace_task(&mut state.tasks, *value, row.seq)?;
        }
        JournalPayload::WorkstreamRecorded(value) => {
            replace_workstream(&mut state.workstreams, *value, row.seq)?;
        }
        JournalPayload::WorkBindingRecorded(value) => {
            replace_work_binding(&mut state.work_bindings, *value, row.seq)?;
        }
        JournalPayload::AttemptRecorded(value) => record_attempt(
            &mut state.attempts,
            &mut state.attempt_revisions,
            *value,
            row.seq,
        )?,
        JournalPayload::CompetingAttemptGroupRecorded(value) => record_competing_group(
            &mut state.competing_groups,
            &mut state.competing_group_revisions,
            *value,
            row.seq,
        )?,
        JournalPayload::OperationBurstRecorded(value) => record_operation_burst(
            &mut state.operation_bursts,
            &mut state.operation_burst_revisions,
            *value,
            row.seq,
        )?,
        JournalPayload::WorkEpisodeRecorded(value) => record_episode(
            &mut state.episodes,
            &mut state.episode_revisions,
            *value,
            row.seq,
        )?,
        JournalPayload::WorkCheckpointRecorded(value) => {
            record_checkpoint(&mut state.checkpoints, *value, row.seq)?;
        }
        JournalPayload::SegmentationCorrectionRecorded(value) => {
            record_correction(&mut state.corrections, *value, row.seq)?;
        }
        JournalPayload::RecoveryCaptureRequestRecorded(value) => recovery::record_request(
            &mut state.recovery_requests,
            &mut state.recovery_request_revisions,
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::RecoveryBundleRecorded(value) => recovery::record_bundle(
            &mut state.recovery_bundles,
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::RecoveryApplicationRecorded(value) => recovery::record_application(
            &mut state.recovery_applications,
            &mut state.recovery_application_revisions,
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::ExperimentRunRecorded(value) => record_run(
            &mut state.experiment_runs,
            Some(&mut state.experiment_run_revisions),
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::ResultEvidenceRecorded(value) => record_result(
            &mut state.result_evidence,
            Some(&mut state.result_evidence_revisions),
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::WorkArtifactRecorded(value) => record_artifact(
            &mut state.work_artifacts,
            Some(&mut state.artifact_revisions),
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::AtomRecorded(value) => semantic::record_atom(
            &mut state.atoms,
            &mut state.atom_revisions,
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        JournalPayload::RevisionProposalRecorded(value) => semantic::record_proposal(
            &mut state.proposals,
            &mut state.proposal_revisions,
            *value,
            row.seq,
            StoreError::StoreCorrupt,
        )?,
        payload @ (JournalPayload::ProcedureRevisionRecorded(_)
        | JournalPayload::ProcedureStateRecorded(_)
        | JournalPayload::ProcedureUsageRecorded(_)
        | JournalPayload::ProcedureNegativeEvidenceRecorded(_)
        | JournalPayload::ProcedureNegativeReviewRecorded(_)) => {
            state.procedure.apply(payload, row.seq)?;
        }
        payload @ (JournalPayload::ScenarioRecorded(_)
        | JournalPayload::CoreMembershipRecorded(_)
        | JournalPayload::GlobalSupportContractRecorded(_)
        | JournalPayload::GlobalSupportValidationRecorded(_)) => {
            state.s23.apply(payload, row.seq)?;
        }
        payload @ (JournalPayload::SemanticDigestRecorded(_)
        | JournalPayload::SemanticDerivationRunRecorded(_)) => {
            state.synthesis.apply(payload, row.seq)?;
        }
        JournalPayload::RecallLedgerRecorded(value) => {
            state.recall_ledger.apply(*value, row.seq)?;
        }
        JournalPayload::SessionImportEventRecorded(value) => {
            let next = crate::session_import::apply_session_event(
                state.session_imports.get(&value.session_id),
                &value,
                row.seq,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            state.session_imports.insert(value.session_id.clone(), next);
        }
    }
    Ok(())
}

fn validate_job_successor(
    current: &DurableJob,
    next: &DurableJob,
    occurred_at_us: i64,
) -> Result<(), StoreError> {
    if current.job_id != next.job_id
        || current.idempotency_key != next.idempotency_key
        || current.target_revision != next.target_revision
        || current.target_watermark != next.target_watermark
        || current.target_generation != next.target_generation
        || current.kind != next.kind
        || current.algorithm_revision != next.algorithm_revision
        || current.model_id != next.model_id
        || current.priority != next.priority
        || current.config_hash != next.config_hash
        || current.budget != next.budget
        || next.attempt < current.attempt
    {
        return Err(StoreError::StoreCorrupt);
    }
    let queued_cancellation = current.state == JobStatus::Queued
        && next.state == JobStatus::Failed
        && next.attempt == current.attempt
        && current.lease_until_us.is_none()
        && next.lease_until_us.is_none()
        && matches!(
            next.terminal.as_deref().map(|terminal| terminal.reason),
            Some(
                JobTerminalReason::Revoked
                    | JobTerminalReason::SourceReplaced
                    | JobTerminalReason::SourceUnavailable
                    | JobTerminalReason::Unsupported
                    | JobTerminalReason::StaleGeneration
            )
        );
    let valid = match (current.state, next.state) {
        (JobStatus::Leased, JobStatus::Succeeded | JobStatus::Failed) => {
            next.attempt == current.attempt
        }
        (JobStatus::Leased, JobStatus::Queued) => next.attempt >= current.attempt,
        (JobStatus::Failed, JobStatus::Queued) => {
            next.attempt > current.attempt
                && current
                    .backoff_until_us
                    .is_none_or(|deadline| deadline <= occurred_at_us)
        }
        _ => queued_cancellation,
    };
    if !valid {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn validate_source_ingest_watermark(
    state: &ReducerState,
    watermark: &SourceIngestWatermark,
    command: &[&JournalRow],
) -> Result<(), StoreError> {
    let codex = validate_confirmed_session_prefix(watermark)?;
    let key = watermark.stable_key();
    let current = state.source_watermarks.get(&key).map(|(value, _)| value);
    let mut receipt = None;
    for row in command {
        let JournalPayload::SourceReceiptRecorded(value) = row.payload()? else {
            continue;
        };
        if value.source_instance_id == watermark.source_instance_id
            && value.source_revision == watermark.source_revision
            && receipt.replace(*value).is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    if let Some(current) = current {
        match watermark.source_sequence.cmp(&current.source_sequence) {
            std::cmp::Ordering::Less if codex => return Err(StoreError::StoreCorrupt),
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                if watermark == current && receipt.is_none() {
                    return Ok(());
                }
                if codex {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }
    let receipt = receipt.ok_or(StoreError::StoreCorrupt)?;
    if receipt.source_sequence != watermark.source_sequence {
        return Err(StoreError::StoreCorrupt);
    }
    if !codex {
        return Ok(());
    }
    let range = receipt
        .source_byte_range
        .as_ref()
        .ok_or(StoreError::StoreCorrupt)?;
    let previous = if let Some(current) = current {
        if range.start != current.source_sequence {
            return Err(StoreError::StoreCorrupt);
        }
        Some(
            current
                .confirmed_prefix_digest
                .clone()
                .ok_or(StoreError::StoreCorrupt)?,
        )
    } else {
        if range.start != 0 {
            return Err(StoreError::StoreCorrupt);
        }
        None
    };
    if range.end != watermark.source_sequence || range.end <= range.start {
        return Err(StoreError::StoreCorrupt);
    }
    let digest = sha256(
        "session_import_confirmed_prefix",
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(watermark.source_instance_id.as_str().to_owned()),
            CanonicalValue::String(watermark.source_revision.as_str().to_owned()),
            CanonicalValue::Integer(i128::from(range.start)),
            CanonicalValue::Integer(i128::from(range.end)),
            previous.map_or(CanonicalValue::Null, CanonicalValue::String),
            CanonicalValue::String(receipt.cas_ref),
        ]),
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let digest = hex(&digest);
    if watermark.confirmed_prefix_digest.as_deref() != Some(digest.as_str()) {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn validate_confirmed_session_prefix(
    watermark: &SourceIngestWatermark,
) -> Result<bool, StoreError> {
    let codex = watermark
        .source_instance_id
        .as_str()
        .strip_prefix("codex-session:")
        .is_some();
    match (codex, watermark.confirmed_prefix_digest.is_some()) {
        (true, true) | (false, false) => Ok(codex),
        _ => Err(StoreError::StoreCorrupt),
    }
}

fn replace_occurrence(
    values: &mut BTreeMap<HostOccurrenceId, (HostOccurrence, u64)>,
    value: HostOccurrence,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.host_occurrence_id)
        && current != &value
        && (value.normalization_revision != current.normalization_revision + 1
            || value.previous_normalization_revision != Some(current.normalization_revision))
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.host_occurrence_id, (value, seq));
    Ok(())
}

fn replace_task(
    values: &mut BTreeMap<TaskId, (Task, u64)>,
    value: Task,
    seq: u64,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    match values.get(&value.task_id) {
        None => {
            if value.predecessor_revision_id.is_some() {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Some((current, _)) if current == &value => {}
        Some((current, _)) => {
            if value.revision_id == current.revision_id
                || value.predecessor_revision_id != Some(current.revision_id)
                || value.created_at_us != current.created_at_us
                || value.source_watermark <= current.source_watermark
                || current.lifecycle.is_terminal()
                || value.continuation_of_task_id != current.continuation_of_task_id
                || value.split_from_task_id != current.split_from_task_id
                || value.merged_from_task_ids != current.merged_from_task_ids
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    values.insert(value.task_id, (value, seq));
    Ok(())
}

fn replace_workstream(
    values: &mut BTreeMap<WorkstreamId, (Workstream, u64)>,
    value: Workstream,
    seq: u64,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    match values.get(&value.workstream_id) {
        None => {
            if value.predecessor_revision_id.is_some() {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Some((current, _)) if current == &value => {}
        Some((current, _)) => {
            if value.revision_id == current.revision_id
                || value.predecessor_revision_id != Some(current.revision_id)
                || value.task_id != current.task_id
                || value.repository_instance_id != current.repository_instance_id
                || value.root_goal != current.root_goal
                || value.source_watermark <= current.source_watermark
                || current.status.is_terminal()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    values.insert(value.workstream_id, (value, seq));
    Ok(())
}

fn replace_work_binding(
    values: &mut BTreeMap<WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    value: WorkBindingRevision,
    seq: u64,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if let Some((existing, _)) = values.get(&value.work_binding_revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    values.insert(value.work_binding_revision_id, (value, seq));
    Ok(())
}

fn replace_attempt(
    values: &mut BTreeMap<AttemptId, (Attempt, u64)>,
    value: Attempt,
    seq: u64,
) -> Result<(), StoreError> {
    match values.get(&value.attempt_id) {
        None if value.validate().is_err()
            || value.revision_generation != 1
            || value.predecessor_revision_id.is_some() =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        None => {}
        Some((current, _)) if current == &value => return Ok(()),
        Some((current, _)) => {
            current
                .validate_successor(&value)
                .map_err(|_| StoreError::StoreCorrupt)?;
        }
    }
    values.insert(value.attempt_id, (value, seq));
    Ok(())
}

fn record_attempt(
    current: &mut BTreeMap<AttemptId, (Attempt, u64)>,
    revisions: &mut BTreeMap<evertrace_domain::revision::RevisionId, (Attempt, u64)>,
    value: Attempt,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = revisions.get(&value.revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    replace_attempt(current, value.clone(), seq)?;
    revisions.insert(value.revision_id, (value, seq));
    Ok(())
}

fn replace_competing_group(
    values: &mut BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    value: CompetingAttemptGroup,
    seq: u64,
) -> Result<(), StoreError> {
    match values.get(&value.competing_group_id) {
        None if value.validate().is_err()
            || value.revision_generation != 1
            || value.predecessor_revision_id.is_some()
            || value.resolution_status != CompetingResolutionStatus::Open =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        None => {}
        Some((current, _)) if current == &value => return Ok(()),
        Some((current, _)) => current
            .validate_successor(&value)
            .map_err(|_| StoreError::StoreCorrupt)?,
    }
    values.insert(value.competing_group_id, (value, seq));
    Ok(())
}

fn record_competing_group(
    current: &mut BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    revisions: &mut BTreeMap<evertrace_domain::revision::RevisionId, (CompetingAttemptGroup, u64)>,
    value: CompetingAttemptGroup,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = revisions.get(&value.revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    replace_competing_group(current, value.clone(), seq)?;
    revisions.insert(value.revision_id, (value, seq));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_work_binding_relations(
    bindings: &BTreeMap<WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    operations: &BTreeMap<OperationId, (Operation, u64)>,
    scope_effects: &BTreeMap<ScopeEffectId, (ScopeEffect, u64)>,
    tasks: &BTreeMap<TaskId, (Task, u64)>,
    workstreams: &BTreeMap<WorkstreamId, (Workstream, u64)>,
    attempts: &BTreeMap<AttemptId, (Attempt, u64)>,
    groups: &BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    episodes: &BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    runs: &BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
) -> Result<(), StoreError> {
    current_binding_lineage(bindings.values().map(|(binding, _)| binding))?;
    for (binding, _) in bindings.values() {
        binding.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let (operation, _) = operations
            .get(&binding.operation_id)
            .ok_or(StoreError::StoreCorrupt)?;
        for scope_id in &binding.scope_effect_refs {
            let (effect, _) = scope_effects
                .get(scope_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if effect.operation_id != binding.operation_id
                || !operation.scope_effect_ids.contains(scope_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }

        match (
            binding.primary_binding.task_id,
            binding.primary_binding.workstream_id,
        ) {
            (Some(task_id), Some(workstream_id)) => {
                let (task, _) = tasks.get(&task_id).ok_or(StoreError::StoreCorrupt)?;
                let (workstream, _) = workstreams
                    .get(&workstream_id)
                    .ok_or(StoreError::StoreCorrupt)?;
                if workstream.task_id != task_id
                    || (binding.assignment_status == AssignmentStatus::Resolved
                        && task.identity_confidence == TaskIdentityConfidence::Provisional)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                for scope_id in &binding.scope_effect_refs {
                    let (effect, _) = &scope_effects[scope_id];
                    if effect.repository_instance_id.is_some_and(|repository_id| {
                        workstream.repository_instance_id != Some(repository_id)
                    }) || effect.worktree_instance_id.is_some_and(|worktree_id| {
                        !workstream.worktree_instance_ids.contains(&worktree_id)
                    }) {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                if binding.primary_binding.attempt_id.is_some()
                    || binding.primary_binding.competing_group_id.is_some()
                {
                    if binding.assignment_status != AssignmentStatus::Resolved {
                        return Err(StoreError::StoreCorrupt);
                    }
                    if let Some(attempt_id) = binding.primary_binding.attempt_id {
                        let attempt = &attempts.get(&attempt_id).ok_or(StoreError::StoreCorrupt)?.0;
                        if attempt.task_id != task_id
                            || attempt.workstream_id != workstream_id
                            || !attempt
                                .work_binding_revision_refs
                                .contains(&binding.work_binding_revision_id)
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                    if let Some(group_id) = binding.primary_binding.competing_group_id {
                        let group = &groups.get(&group_id).ok_or(StoreError::StoreCorrupt)?.0;
                        if group.task_id != task_id
                            || !group.member_workstream_ids.contains(&workstream_id)
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                }
                if let Some(episode_id) = binding.primary_binding.episode_id {
                    let episode = &episodes.get(&episode_id).ok_or(StoreError::StoreCorrupt)?.0;
                    if binding.assignment_status != AssignmentStatus::Resolved
                        || episode.task_id != task_id
                        || episode.workstream_id != workstream_id
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                if let Some(run_id) = binding.primary_binding.experiment_run_id {
                    let run = &runs.get(&run_id).ok_or(StoreError::StoreCorrupt)?.0;
                    let run_attempt_id = run.attempt_id.ok_or(StoreError::StoreCorrupt)?;
                    let attempt = &attempts
                        .get(&run_attempt_id)
                        .ok_or(StoreError::StoreCorrupt)?
                        .0;
                    if binding.assignment_status != AssignmentStatus::Resolved
                        || binding.primary_binding.attempt_id != Some(run_attempt_id)
                        || run.workstream_id != workstream_id
                        || attempt.task_id != task_id
                        || attempt.workstream_id != workstream_id
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
            }
            (None, None) => {
                if binding.assignment_status == AssignmentStatus::Resolved {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            _ => return Err(StoreError::StoreCorrupt),
        }
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct CompetingSelectedCohort {
    typed_evidence_refs: Vec<String>,
}

fn derive_competing_selected_cohort<'a>(
    attempt: &Attempt,
    mut integration: impl FnMut(&IntegrationEventId) -> Option<&'a IntegrationEvent>,
    mut result: impl FnMut(&ResultEvidenceId) -> Option<&'a ResultEvidence>,
    mut run: impl FnMut(&RevisionId) -> Option<&'a ExperimentRun>,
) -> Option<CompetingSelectedCohort> {
    if attempt.adoption_status != AttemptAdoptionStatus::Integrated
        || attempt.verification != AttemptVerification::Passed
        || attempt.validate().is_err()
    {
        return None;
    }
    let integration_ids = attempt
        .integration_event_refs
        .iter()
        .copied()
        .filter(|id| {
            integration(id).is_some_and(|event| {
                event.validate().is_ok()
                    && event.assessment == LineageAssessment::Proven
                    && event.integrated_attempt_ids.contains(&attempt.attempt_id)
            })
        })
        .collect::<BTreeSet<_>>();
    if integration_ids.is_empty() {
        return None;
    }

    let mut result_ids = BTreeSet::new();
    for result_id in attempt
        .parent_verification_refs
        .iter()
        .filter_map(|reference| reference.parse::<ResultEvidenceId>().ok())
    {
        let Some(result) = result(&result_id) else {
            continue;
        };
        if result.validate().is_err()
            || result.result_evidence_id != result_id
            || result.result_scope != ResultScope::Complete
            || result.completeness != EvidenceCompleteness::Complete
            || result.parser_receipt.status != ParserStatus::Parsed
            || result
                .verifier_receipt
                .as_ref()
                .is_none_or(|receipt| receipt.status != VerifierStatus::Passed)
        {
            continue;
        }
        let Some(run) = run(&result.experiment_run_revision_id) else {
            continue;
        };
        if run.validate().is_err()
            || run.revision_id != result.experiment_run_revision_id
            || run.run_id != result.experiment_run_id
            || run.attempt_binding_status != AttemptBindingStatus::Resolved
            || run.attempt_id != Some(attempt.attempt_id)
            || run.observability != RunObservability::Full
            || run.execution_status != RunExecutionStatus::Completed
            || run.contract_validity != RunContractValidity::Valid
            || run.workstream_id != attempt.workstream_id
            || run.strategy_contract_fingerprint != attempt.strategy_contract_fingerprint
        {
            continue;
        }
        result_ids.insert(result.result_evidence_id);
    }
    if result_ids.is_empty() {
        return None;
    }

    let mut typed_evidence_refs = integration_ids
        .iter()
        .map(ToString::to_string)
        .chain(result_ids.iter().map(ToString::to_string))
        .collect::<Vec<_>>();
    typed_evidence_refs.sort();
    typed_evidence_refs.dedup();
    Some(CompetingSelectedCohort {
        typed_evidence_refs,
    })
}

fn competing_selected_resolution_refs(
    current: &CompetingAttemptGroup,
    cohort: &CompetingSelectedCohort,
) -> Vec<String> {
    let mut refs = current.resolution_evidence_refs.clone();
    refs.extend(cohort.typed_evidence_refs.iter().cloned());
    refs.sort();
    refs.dedup();
    refs
}

fn canonical_mark_new_attempt_child(
    source: &Attempt,
    candidate: &Attempt,
    source_watermark: u64,
) -> Result<Attempt, StoreError> {
    let child = Attempt {
        attempt_id: candidate.attempt_id,
        revision_id: candidate.revision_id,
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: source.task_id,
        workstream_id: source.workstream_id,
        episode_id: None,
        repository_instance_id: source.repository_instance_id,
        worktree_instance_ids: source.worktree_instance_ids.clone(),
        execution_lane_ids: Vec::new(),
        competing_group_ids: Vec::new(),
        experiment_run_ids: Vec::new(),
        execution_status: AttemptExecutionStatus::Proposed,
        adoption_status: AttemptAdoptionStatus::None,
        verification: AttemptVerification::Unverified,
        lifecycle_status: AttemptLifecycleStatus::Active,
        strategy_contract: source.strategy_contract.clone(),
        strategy_contract_fingerprint: source.strategy_contract_fingerprint,
        resumes_from_attempt_id: Some(source.attempt_id),
        composed_from_attempt_ids: Vec::new(),
        resume_event_refs: vec![source.revision_id.to_string()],
        resume_state_assessment: Some(ResumeStateAssessment::Unknown),
        resume_source_snapshot_id: None,
        resume_target_snapshot_id: None,
        worktree_transition_refs: Vec::new(),
        integration_event_refs: Vec::new(),
        recovery_bundle_refs: Vec::new(),
        recovery_application_refs: Vec::new(),
        work_binding_revision_refs: Vec::new(),
        local_outcome_refs: Vec::new(),
        parent_verification_refs: Vec::new(),
        outcome_refs: Vec::new(),
        outcome_state: AttemptOutcomeState::Unknown,
        interruption_refs: Vec::new(),
        interruption_reason: None,
        explicit_abandon_refs: Vec::new(),
        supersede_evidence_refs: Vec::new(),
        failure_signature: None,
        source_watermark,
    };
    child.validate().map_err(|_| StoreError::StoreCorrupt)?;
    Ok(child)
}

#[allow(clippy::too_many_arguments)]
fn validate_attempt_relations(
    attempts: &BTreeMap<AttemptId, (Attempt, u64)>,
    attempt_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (Attempt, u64)>,
    groups: &BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    _tasks: &BTreeMap<TaskId, (Task, u64)>,
    workstreams: &BTreeMap<WorkstreamId, (Workstream, u64)>,
    execution_lanes: &BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    worktree_snapshots: &BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    worktree_transitions: &BTreeMap<WorktreeTransitionId, (WorktreeTransition, u64)>,
    integration_events: &BTreeMap<IntegrationEventId, (IntegrationEvent, u64)>,
    work_bindings: &BTreeMap<WorkBindingRevisionId, (WorkBindingRevision, u64)>,
) -> Result<(), StoreError> {
    fn composition_cycle(
        id: AttemptId,
        attempts: &BTreeMap<AttemptId, (Attempt, u64)>,
        visiting: &mut BTreeSet<AttemptId>,
        visited: &mut BTreeSet<AttemptId>,
    ) -> bool {
        if visited.contains(&id) {
            return false;
        }
        if !visiting.insert(id) {
            return true;
        }
        let cyclic = attempts.get(&id).is_some_and(|value| {
            value
                .0
                .composed_from_attempt_ids
                .iter()
                .any(|source| composition_cycle(*source, attempts, visiting, visited))
        });
        visiting.remove(&id);
        visited.insert(id);
        cyclic
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    if attempts
        .keys()
        .copied()
        .any(|id| composition_cycle(id, attempts, &mut visiting, &mut visited))
    {
        return Err(StoreError::StoreCorrupt);
    }
    for (event, _) in integration_events.values() {
        for attempt_id in &event.integrated_attempt_ids {
            let attempt = &attempts.get(attempt_id).ok_or(StoreError::StoreCorrupt)?.0;
            if !attempt
                .integration_event_refs
                .contains(&event.integration_event_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for (attempt, _) in attempts.values() {
        let workstream = &workstreams
            .get(&attempt.workstream_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if workstream.task_id != attempt.task_id
            || attempt.repository_instance_id != workstream.repository_instance_id
            || attempt
                .worktree_instance_ids
                .iter()
                .any(|id| !workstream.worktree_instance_ids.contains(id))
            || attempt.execution_lane_ids.iter().any(|id| {
                !execution_lanes.contains_key(id) || !workstream.execution_lane_ids.contains(id)
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        let lanes = attempt
            .execution_lane_ids
            .iter()
            .map(|id| &execution_lanes[id].0)
            .collect::<Vec<_>>();
        match attempt.execution_status {
            AttemptExecutionStatus::Proposed | AttemptExecutionStatus::Abandoned => {}
            AttemptExecutionStatus::Active => {
                if !lanes.iter().any(|lane| lane.status == LaneStatus::Active) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            AttemptExecutionStatus::Interrupted => {
                if lanes.iter().any(|lane| {
                    !matches!(
                        lane.status,
                        LaneStatus::Interrupted | LaneStatus::InterruptedUnconfirmed
                    )
                }) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            AttemptExecutionStatus::Completed => {
                let has_normal_terminal = lanes
                    .iter()
                    .any(|lane| matches!(lane.status, LaneStatus::Returned | LaneStatus::Stopped));
                if lanes
                    .iter()
                    .any(|lane| matches!(lane.status, LaneStatus::Active | LaneStatus::Unresolved))
                    || (!has_normal_terminal && attempt.outcome_state != AttemptOutcomeState::Known)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        if let Some(predecessor_id) = attempt.predecessor_revision_id {
            let predecessor = &attempt_revisions
                .get(&predecessor_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if predecessor.execution_status == AttemptExecutionStatus::Interrupted
                && attempt.execution_status == AttemptExecutionStatus::Active
            {
                let new_lanes = attempt
                    .execution_lane_ids
                    .iter()
                    .filter(|id| !predecessor.execution_lane_ids.contains(id))
                    .collect::<Vec<_>>();
                if new_lanes.is_empty()
                    || new_lanes
                        .iter()
                        .any(|id| execution_lanes[*id].0.status != LaneStatus::Active)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                let target_id = attempt
                    .resume_target_snapshot_id
                    .ok_or(StoreError::StoreCorrupt)?;
                let target = &worktree_snapshots
                    .get(&target_id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                if !attempt
                    .worktree_instance_ids
                    .contains(&target.worktree_instance_id)
                    || !workstream
                        .worktree_instance_ids
                        .contains(&target.worktree_instance_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                match attempt.resume_state_assessment {
                    Some(ResumeStateAssessment::CompatibleSameInstance) => {
                        if let Some(source_id) = attempt.resume_source_snapshot_id {
                            let source = &worktree_snapshots
                                .get(&source_id)
                                .ok_or(StoreError::StoreCorrupt)?
                                .0;
                            if source.worktree_instance_id != target.worktree_instance_id {
                                return Err(StoreError::StoreCorrupt);
                            }
                        } else if !predecessor
                            .worktree_instance_ids
                            .contains(&target.worktree_instance_id)
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                    Some(ResumeStateAssessment::CompatibleLineageTransfer) => {
                        let source_id = attempt
                            .resume_source_snapshot_id
                            .ok_or(StoreError::StoreCorrupt)?;
                        let source = &worktree_snapshots
                            .get(&source_id)
                            .ok_or(StoreError::StoreCorrupt)?
                            .0;
                        let topology = attempt.worktree_transition_refs.iter().any(|id| {
                            worktree_transitions.get(id).is_some_and(|value| {
                                value.0.from_worktree_instance_id == source.worktree_instance_id
                                    && value.0.from_snapshot_id == Some(source_id)
                                    && value.0.to_worktree_instance_id
                                        == target.worktree_instance_id
                                    && value.0.to_snapshot_id == Some(target_id)
                            })
                        });
                        if !predecessor
                            .worktree_instance_ids
                            .contains(&source.worktree_instance_id)
                            || !topology
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                    _ => return Err(StoreError::StoreCorrupt),
                }
            }
        }
        for snapshot_id in [
            attempt.resume_source_snapshot_id,
            attempt.resume_target_snapshot_id,
        ]
        .into_iter()
        .flatten()
        {
            let snapshot = &worktree_snapshots
                .get(&snapshot_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if !attempt
                .worktree_instance_ids
                .contains(&snapshot.worktree_instance_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if attempt
            .worktree_transition_refs
            .iter()
            .any(|id| !worktree_transitions.contains_key(id))
            || attempt.integration_event_refs.iter().any(|id| {
                integration_events.get(id).is_none_or(|event| {
                    !event.0.integrated_attempt_ids.contains(&attempt.attempt_id)
                })
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        for binding_id in &attempt.work_binding_revision_refs {
            let binding = &work_bindings
                .get(binding_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if binding.assignment_status != AssignmentStatus::Resolved
                || binding.primary_binding.task_id != Some(attempt.task_id)
                || binding.primary_binding.workstream_id != Some(attempt.workstream_id)
                || binding.primary_binding.attempt_id != Some(attempt.attempt_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for source in attempt
            .composed_from_attempt_ids
            .iter()
            .chain(attempt.resumes_from_attempt_id.iter())
        {
            let source_attempt = &attempts.get(source).ok_or(StoreError::StoreCorrupt)?.0;
            if source_attempt.task_id != attempt.task_id
                || (attempt.composed_from_attempt_ids.contains(source)
                    && source_attempt.strategy_contract_fingerprint
                        == attempt.strategy_contract_fingerprint)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for group_id in &attempt.competing_group_ids {
            let group = &groups.get(group_id).ok_or(StoreError::StoreCorrupt)?.0;
            if !group.member_attempt_ids.contains(&attempt.attempt_id) {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for (group, _) in groups.values() {
        if group.origin_workstream_id.is_some_and(|id| {
            workstreams
                .get(&id)
                .is_none_or(|value| value.0.task_id != group.task_id)
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        for member_id in &group.member_attempt_ids {
            let attempt = &attempts.get(member_id).ok_or(StoreError::StoreCorrupt)?.0;
            if attempt.task_id != group.task_id
                || !group.member_workstream_ids.contains(&attempt.workstream_id)
                || !attempt
                    .competing_group_ids
                    .contains(&group.competing_group_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if group.member_workstream_ids.iter().any(|id| {
            workstreams
                .get(id)
                .is_none_or(|value| value.0.task_id != group.task_id)
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        for candidate in &group.candidate_snapshot_refs {
            let attempt = &attempts
                .get(&candidate.attempt_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let snapshot = &worktree_snapshots
                .get(&candidate.snapshot_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if !group.member_attempt_ids.contains(&candidate.attempt_id)
                || attempt.workstream_id != candidate.workstream_id
                || !attempt
                    .worktree_instance_ids
                    .contains(&snapshot.worktree_instance_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if let Some(selected) = group.selected_attempt_id {
            let attempt = &attempts[&selected].0;
            if attempt.adoption_status != AttemptAdoptionStatus::Integrated
                || attempt.verification != AttemptVerification::Passed
                || !attempt
                    .parent_verification_refs
                    .iter()
                    .any(|evidence| group.resolution_evidence_refs.contains(evidence))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if group.resolution_status == CompetingResolutionStatus::PartiallyIntegrated
            && group.partially_integrated_attempt_ids.iter().any(|id| {
                attempts.get(id).is_none_or(|value| {
                    !matches!(
                        value.0.adoption_status,
                        AttemptAdoptionStatus::PartiallyIntegrated
                            | AttemptAdoptionStatus::Integrated
                    )
                })
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(())
}

fn validate_work_identity_relations(
    tasks: &BTreeMap<TaskId, (Task, u64)>,
    workstreams: &BTreeMap<WorkstreamId, (Workstream, u64)>,
    repositories: &BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    worktrees: &BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
) -> Result<(), StoreError> {
    for (task, _) in tasks.values() {
        for referenced in task
            .continuation_of_task_id
            .iter()
            .chain(task.split_from_task_id.iter())
            .chain(task.split_into_task_ids.iter())
            .chain(task.merged_from_task_ids.iter())
            .chain(task.merged_into_task_id.iter())
        {
            if !tasks.contains_key(referenced) {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for membership in &task.scope_memberships {
            if let Some(repository_id) = membership.repository_instance_id {
                if !repositories.contains_key(&repository_id) {
                    return Err(StoreError::StoreCorrupt);
                }
                for worktree_id in &membership.worktree_instance_ids {
                    let (worktree, _) =
                        worktrees.get(worktree_id).ok_or(StoreError::StoreCorrupt)?;
                    if worktree.repository_instance_id != repository_id {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
            }
        }
    }
    for (workstream, _) in workstreams.values() {
        let (task, _) = tasks
            .get(&workstream.task_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if let Some(repository_id) = workstream.repository_instance_id {
            let membership = task
                .scope_memberships
                .iter()
                .find(|membership| membership.repository_instance_id == Some(repository_id))
                .ok_or(StoreError::StoreCorrupt)?;
            if workstream
                .worktree_instance_ids
                .iter()
                .any(|id| !membership.worktree_instance_ids.contains(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
            for worktree_id in &workstream.worktree_instance_ids {
                let (worktree, _) = worktrees.get(worktree_id).ok_or(StoreError::StoreCorrupt)?;
                if worktree.repository_instance_id != repository_id {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        for dependency_id in workstream
            .dependency_workstream_ids
            .iter()
            .chain(workstream.parent_workstream_id.iter())
        {
            let (dependency, _) = workstreams
                .get(dependency_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if dependency.task_id != workstream.task_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    fn visit(
        id: WorkstreamId,
        workstreams: &BTreeMap<WorkstreamId, (Workstream, u64)>,
        visiting: &mut BTreeSet<WorkstreamId>,
        visited: &mut BTreeSet<WorkstreamId>,
    ) -> Result<(), StoreError> {
        if visited.contains(&id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(StoreError::StoreCorrupt);
        }
        let (workstream, _) = workstreams.get(&id).ok_or(StoreError::StoreCorrupt)?;
        for dependency in &workstream.dependency_workstream_ids {
            visit(*dependency, workstreams, visiting, visited)?;
        }
        visiting.remove(&id);
        visited.insert(id);
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in workstreams.keys() {
        visit(*id, workstreams, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn replace_operation(
    values: &mut BTreeMap<OperationId, (Operation, u64)>,
    value: Operation,
    seq: u64,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    match values.get(&value.operation_id) {
        None if value.operation_revision != 1 || value.previous_operation_revision.is_some() => {
            return Err(StoreError::StoreCorrupt);
        }
        Some((current, _))
            if current != &value
                && (current.operation_revision.checked_add(1)
                    != Some(value.operation_revision)
                    || value.previous_operation_revision != Some(current.operation_revision)) =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        _ => {}
    }
    values.insert(value.operation_id, (value, seq));
    Ok(())
}

fn replace_lane(
    values: &mut BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    value: ExecutionLane,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.execution_lane_id)
        && (value.lane_revision != current.lane_revision + 1
            || value.predecessor_revision != Some(current.lane_revision))
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.execution_lane_id, (value, seq));
    Ok(())
}

fn replace_capture_receipt(
    values: &mut BTreeMap<ExecutionLaneId, (CaptureReceipt, u64)>,
    value: CaptureReceipt,
    seq: u64,
) -> Result<(), StoreError> {
    match values.get(&value.execution_lane_id) {
        None if value.predecessor_revision_id.is_some() => {
            return Err(StoreError::StoreCorrupt);
        }
        Some((current, _))
            if value.capture_receipt_revision_id == current.capture_receipt_revision_id
                || value.predecessor_revision_id != Some(current.capture_receipt_revision_id) =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        _ => {}
    }
    values.insert(value.execution_lane_id, (value, seq));
    Ok(())
}

fn record_capture_receipt(
    current: &mut BTreeMap<ExecutionLaneId, (CaptureReceipt, u64)>,
    revisions: &mut BTreeMap<evertrace_domain::ids::CaptureReceiptId, (CaptureReceipt, u64)>,
    value: CaptureReceipt,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = revisions.get(&value.capture_receipt_revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    replace_capture_receipt(current, value.clone(), seq)?;
    revisions.insert(value.capture_receipt_revision_id, (value, seq));
    Ok(())
}

fn replace_gap(
    values: &mut BTreeMap<String, (CaptureGapMarkerEvidence, u64)>,
    value: CaptureGapMarkerEvidence,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.marker_id)
        && (value.reconciliation_revision != current.reconciliation_revision + 1
            || value.predecessor_revision != Some(current.reconciliation_revision))
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.marker_id.clone(), (value, seq));
    Ok(())
}

fn replace_outage(
    values: &mut BTreeMap<CaptureOutageIntervalId, (CaptureOutageInterval, u64)>,
    value: CaptureOutageInterval,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.capture_outage_interval_id)
        && (value.reconciliation_revision != current.reconciliation_revision + 1
            || value.predecessor_revision != Some(current.reconciliation_revision))
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.capture_outage_interval_id, (value, seq));
    Ok(())
}

impl ReducerState {
    fn rebuild_revision_currents(&mut self) -> Result<(), StoreError> {
        self.host_occurrences.clear();
        let mut occurrences = self
            .host_occurrence_revisions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        occurrences
            .sort_by_key(|(value, _)| (value.host_occurrence_id, value.normalization_revision));
        for (value, seq) in occurrences {
            replace_occurrence(&mut self.host_occurrences, value, seq)?;
        }
        self.operations.clear();
        let mut operations = self
            .operation_revisions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        operations.sort_by_key(|(value, _)| (value.operation_id, value.operation_revision));
        for (value, seq) in operations {
            replace_operation(&mut self.operations, value, seq)?;
        }
        self.attempts.clear();
        let mut attempts = self.attempt_revisions.values().cloned().collect::<Vec<_>>();
        attempts.sort_by_key(|(value, _)| (value.attempt_id, value.revision_generation));
        for (value, seq) in attempts {
            replace_attempt(&mut self.attempts, value, seq)?;
        }
        self.competing_groups.clear();
        let mut groups = self
            .competing_group_revisions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        groups.sort_by_key(|(value, _)| (value.competing_group_id, value.revision_generation));
        for (value, seq) in groups {
            replace_competing_group(&mut self.competing_groups, value, seq)?;
        }
        self.operation_bursts.clear();
        let mut bursts = self
            .operation_burst_revisions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        bursts.sort_by_key(|(value, _)| (value.operation_burst_id, value.revision_generation));
        for (value, seq) in bursts {
            if let Some((current, _)) = self.operation_bursts.get(&value.operation_burst_id) {
                current
                    .validate_successor(&value)
                    .map_err(|_| StoreError::StoreCorrupt)?;
            } else {
                value.validate().map_err(|_| StoreError::StoreCorrupt)?;
            }
            self.operation_bursts
                .insert(value.operation_burst_id, (value, seq));
        }
        self.episodes.clear();
        let mut episodes = self.episode_revisions.values().cloned().collect::<Vec<_>>();
        episodes.sort_by_key(|(value, _)| (value.episode_id, value.revision_generation));
        for (value, seq) in episodes {
            match self.episodes.get(&value.episode_id) {
                None => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                }
                Some((current, _)) => {
                    current
                        .validate_successor(&value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                }
            }
            self.episodes.insert(value.episode_id, (value, seq));
        }
        recovery::rebuild_requests(
            &mut self.recovery_requests,
            &self.recovery_request_revisions,
            StoreError::StoreCorrupt,
        )?;
        recovery::rebuild_applications(
            &mut self.recovery_applications,
            &self.recovery_application_revisions,
            StoreError::StoreCorrupt,
        )?;
        autoresearch::rebuild_runs(&mut self.experiment_runs, &self.experiment_run_revisions)?;
        autoresearch::rebuild_results(&mut self.result_evidence, &self.result_evidence_revisions)?;
        autoresearch::rebuild_artifacts(&mut self.work_artifacts, &self.artifact_revisions)?;
        semantic::rebuild_atoms(&mut self.atoms, &self.atom_revisions)?;
        semantic::rebuild_proposals(&mut self.proposals, &self.proposal_revisions)?;
        self.procedure.rebuild()?;
        self.s23.rebuild()?;
        self.synthesis
            .rebuild(&self.episodes, &self.episode_revisions)?;
        Ok(())
    }

    fn from_current_rows(rows: &[ObjectRow], checkpoint_frontier: u64) -> Result<Self, StoreError> {
        let checkpoints = rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Checkpoint)
            .collect::<Vec<_>>();
        if checkpoints.len() != 1
            || checkpoints[0].row_id != OBJECTS_CHECKPOINT_ID
            || checkpoints[0].source_event_seq != checkpoint_frontier
            || checkpoints[0].projection_generation != PROJECTION_GENERATION
        {
            return Err(StoreError::StoreCorrupt);
        }

        let mut state = Self::default();
        for row in rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Data)
        {
            if row.source_event_seq > checkpoint_frontier
                || row.projection_generation != PROJECTION_GENERATION
            {
                return Err(StoreError::StoreCorrupt);
            }
            if recall_projection::contract(row)?.is_some() {
                continue;
            }
            if let Some(value) = crate::session_import::restore_current(row)? {
                if state
                    .session_imports
                    .insert(value.session_id.clone(), value)
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                continue;
            }
            if s23::S23State::restore_projection(row)? {
                continue;
            }
            if synthesis::restore_wiki_projection(row)?.is_some() {
                continue;
            }
            if procedure_effect::restore(row)?.is_some() {
                continue;
            }
            if let Some(need) = recall_ledger::need(row)? {
                state.recall_ledger.restore(row, need)?;
                continue;
            }
            let payload_json = row
                .payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?;
            let payload: JournalPayload =
                serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
            payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
            if payload
                .canonical_json()
                .map_err(|_| StoreError::StoreCorrupt)?
                != payload_json
            {
                return Err(StoreError::StoreCorrupt);
            }
            state.restore_row(row, payload)?;
        }

        state.rebuild_revision_currents()?;
        state.validate_evidence_relations()?;
        let canonical = state.clone().into_snapshot(checkpoint_frontier)?;
        if canonical.rows != rows {
            return Err(StoreError::Projection);
        }
        Ok(state)
    }

    fn restore_row(&mut self, row: &ObjectRow, payload: JournalPayload) -> Result<(), StoreError> {
        let duplicate = match payload {
            JournalPayload::MigrationApplied(value) => {
                require_row(
                    row,
                    ObjectRowClass::Projection,
                    &format!("projection:migration:{}", value.migration_id),
                )?;
                self.migrations
                    .insert(
                        value.migration_id.clone(),
                        (
                            JournalPayload::MigrationApplied(value),
                            row.source_event_seq,
                        ),
                    )
                    .is_some()
            }
            JournalPayload::SegmentationCorrectionRecorded(value) => {
                let value = *value;
                let id = value.correction_revision_id.to_string();
                require_work_identity_row(
                    row,
                    "segmentation_correction",
                    &id,
                    &id,
                    None,
                    None,
                    None,
                    None,
                    value.kind.as_str(),
                )?;
                self.corrections
                    .insert(value.correction_revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::AttemptRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id = format!("object:work:attempt:{}", value.attempt_id);
                require_work_identity_row(
                    &normalized,
                    "attempt",
                    &value.attempt_id.to_string(),
                    &value.revision_id.to_string(),
                    Some(&value.task_id.to_string()),
                    Some(&value.workstream_id.to_string()),
                    value
                        .repository_instance_id
                        .map(|id| id.to_string())
                        .as_deref(),
                    value
                        .worktree_instance_ids
                        .first()
                        .map(ToString::to_string)
                        .as_deref(),
                    value.lifecycle_status.as_str(),
                )?;
                self.attempt_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::CompetingAttemptGroupRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id = format!(
                    "object:work:competing_attempt_group:{}",
                    value.competing_group_id
                );
                require_work_identity_row(
                    &normalized,
                    "competing_attempt_group",
                    &value.competing_group_id.to_string(),
                    &value.revision_id.to_string(),
                    Some(&value.task_id.to_string()),
                    value
                        .origin_workstream_id
                        .map(|id| id.to_string())
                        .as_deref(),
                    None,
                    None,
                    value.resolution_status.as_str(),
                )?;
                self.competing_group_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::OperationBurstRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id =
                    format!("object:work:operation_burst:{}", value.operation_burst_id);
                require_work_identity_row(
                    &normalized,
                    "operation_burst",
                    &value.operation_burst_id.to_string(),
                    &value.revision_id.to_string(),
                    None,
                    None,
                    None,
                    None,
                    value.lifecycle.as_str(),
                )?;
                self.operation_burst_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorkEpisodeRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id = format!("object:work:work_episode:{}", value.episode_id);
                require_work_identity_row(
                    &normalized,
                    "work_episode",
                    &value.episode_id.to_string(),
                    &value.revision_id.to_string(),
                    Some(&value.task_id.to_string()),
                    Some(&value.workstream_id.to_string()),
                    value
                        .repository_instance_id
                        .map(|id| id.to_string())
                        .as_deref(),
                    value
                        .worktree_instance_id
                        .map(|id| id.to_string())
                        .as_deref(),
                    value.lifecycle_status.as_str(),
                )?;
                self.episode_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorkCheckpointRecorded(value) => {
                let value = *value;
                let key = value.stable_key();
                require_work_identity_row(
                    row,
                    "work_checkpoint",
                    &key,
                    &value.episode_revision_id.to_string(),
                    None,
                    None,
                    None,
                    None,
                    "derived",
                )?;
                self.checkpoints
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::TaskRecorded(value) => {
                let value = *value;
                require_work_identity_row(
                    row,
                    "task",
                    &value.task_id.to_string(),
                    &value.revision_id.to_string(),
                    Some(&value.task_id.to_string()),
                    None,
                    None,
                    None,
                    value.lifecycle.as_str(),
                )?;
                self.tasks
                    .insert(value.task_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorkstreamRecorded(value) => {
                let value = *value;
                require_work_identity_row(
                    row,
                    "workstream",
                    &value.workstream_id.to_string(),
                    &value.revision_id.to_string(),
                    Some(&value.task_id.to_string()),
                    Some(&value.workstream_id.to_string()),
                    value
                        .repository_instance_id
                        .as_ref()
                        .map(ToString::to_string)
                        .as_deref(),
                    value
                        .active_worktree_instance_id
                        .as_ref()
                        .map(ToString::to_string)
                        .as_deref(),
                    value.status.as_str(),
                )?;
                self.workstreams
                    .insert(value.workstream_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorkBindingRecorded(value) => {
                let value = *value;
                require_work_identity_row(
                    row,
                    "work_binding",
                    &value.work_binding_revision_id.to_string(),
                    &value.work_binding_revision_id.to_string(),
                    value
                        .primary_binding
                        .task_id
                        .map(|id| id.to_string())
                        .as_deref(),
                    value
                        .primary_binding
                        .workstream_id
                        .map(|id| id.to_string())
                        .as_deref(),
                    None,
                    None,
                    value.assignment_status.as_str(),
                )?;
                self.work_bindings
                    .insert(
                        value.work_binding_revision_id,
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::DirtyTarget(value) => {
                let key = value.stable_key();
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:dirty:{key}"),
                )?;
                self.dirty
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::OutboxEnqueued(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:outbox:{}", value.outbox_id),
                )?;
                self.outbox
                    .insert(value.outbox_id.clone(), (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::JobState(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:job:{}", value.job_id),
                )?;
                self.jobs
                    .insert(value.job_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::JobLease(_) => return Err(StoreError::StoreCorrupt),
            JournalPayload::WatermarkAdvanced(value) => {
                let key = value.kind.as_str().to_owned();
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:watermark:{key}"),
                )?;
                self.watermarks
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::ConfigAudit(value) => {
                require_row(row, ObjectRowClass::Runtime, "runtime:config:current")?;
                self.config
                    .replace((JournalPayload::ConfigAudit(value), row.source_event_seq))
                    .is_some()
            }
            JournalPayload::StaleGenerationAudit(value) => {
                let event_id = row
                    .row_id
                    .strip_prefix("projection:audit:stale:")
                    .filter(|value| valid_event_id(value))
                    .ok_or(StoreError::StoreCorrupt)?;
                require_row(
                    row,
                    ObjectRowClass::Projection,
                    &format!("projection:audit:stale:{event_id}"),
                )?;
                self.stale_audits
                    .insert(
                        event_id.to_owned(),
                        (
                            JournalPayload::StaleGenerationAudit(value),
                            row.source_event_seq,
                        ),
                    )
                    .is_some()
            }
            JournalPayload::SourceRevisionRecorded(value) => {
                let key = source_revision_key(&value);
                let fields = evidence_fields(
                    format!("object:evidence:source_revision:{key}"),
                    "source_revision",
                    key.clone(),
                    value.source_revision.as_str().to_owned(),
                    None,
                    None,
                    None,
                );
                require_evidence_object_row(row, &fields)?;
                self.source_revisions
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::SourceReceiptRecorded(value) => {
                let value = *value;
                let fields = evidence_fields(
                    format!("object:evidence:source_receipt:{}", value.source_receipt_id),
                    "source_receipt",
                    value.source_receipt_id.to_string(),
                    value.source_receipt_id.to_string(),
                    value.repository_instance_id.map(|id| id.to_string()),
                    value.worktree_instance_id.map(|id| id.to_string()),
                    value.task_id.map(|id| id.to_string()),
                );
                require_evidence_object_row(row, &fields)?;
                self.source_receipts
                    .insert(value.source_receipt_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::SourceObservationRecorded(value) => {
                let value = *value;
                let fields = evidence_fields(
                    format!(
                        "object:evidence:source_observation:{}",
                        value.source_observation_id
                    ),
                    "source_observation",
                    value.source_observation_id.to_string(),
                    value.source_observation_id.to_string(),
                    None,
                    None,
                    None,
                );
                require_evidence_object_row(row, &fields)?;
                self.source_observations
                    .insert(value.source_observation_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::SourceIngestWatermark(value) => {
                let key = value.stable_key();
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:watermark:source:{key}"),
                )?;
                self.source_watermarks
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::EvidenceSurfaceRecorded(value) => {
                let value = *value;
                require_surface_row(row, &value)?;
                self.evidence_surfaces
                    .insert(
                        value.source_observation_revision_ref,
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::HostOccurrenceNormalized(value) => {
                let value = *value;
                if row.row_id
                    != format!(
                        "object:evidence:host_occurrence:{}@{}",
                        value.host_occurrence_id, value.normalization_revision
                    )
                {
                    return Err(StoreError::StoreCorrupt);
                }
                let mut canonical = row.clone();
                canonical.row_id = format!(
                    "object:evidence:host_occurrence:{}",
                    value.host_occurrence_id
                );
                require_physical_row(
                    &canonical,
                    ObjectFamily::Evidence,
                    "host_occurrence",
                    &value.host_occurrence_id.to_string(),
                    &format!(
                        "{}@{}",
                        value.host_occurrence_id, value.normalization_revision
                    ),
                )?;
                self.host_occurrence_revisions
                    .insert(
                        (value.host_occurrence_id, value.normalization_revision),
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::OperationDerived(value) => {
                let value = *value;
                if row.row_id
                    != format!(
                        "object:work:operation:{}@{}",
                        value.operation_id, value.operation_revision
                    )
                {
                    return Err(StoreError::StoreCorrupt);
                }
                let mut canonical = row.clone();
                canonical.row_id = format!("object:work:operation:{}", value.operation_id);
                require_physical_row(
                    &canonical,
                    ObjectFamily::Work,
                    "operation",
                    &value.operation_id.to_string(),
                    &format!("{}@{}", value.operation_id, value.operation_revision),
                )?;
                self.operation_revisions
                    .insert(
                        (value.operation_id, value.operation_revision),
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::ScopeEffectDerived(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "scope_effect",
                    &value.scope_effect_id.to_string(),
                    &value.scope_effect_id.to_string(),
                )?;
                self.scope_effects
                    .insert(value.scope_effect_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::NormalizationWatermark(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!(
                        "runtime:watermark:normalization:{}",
                        value.source_observation_id
                    ),
                )?;
                self.normalization_watermarks
                    .insert(value.source_observation_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::ExecutionLaneRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "execution_lane",
                    &value.execution_lane_id.to_string(),
                    &format!("{}@{}", value.execution_lane_id, value.lane_revision),
                )?;
                let duplicate_revision = self
                    .execution_lane_revisions
                    .insert(
                        (value.execution_lane_id, value.lane_revision),
                        (value.clone(), row.source_event_seq),
                    )
                    .is_some();
                self.execution_lanes
                    .insert(value.execution_lane_id, (value, row.source_event_seq))
                    .is_some()
                    || duplicate_revision
            }
            JournalPayload::CaptureReceiptRecorded(value) => {
                let value = *value;
                let revision_id = value.capture_receipt_revision_id;
                let duplicate_revision = self
                    .capture_receipt_revisions
                    .insert(revision_id, (value.clone(), row.source_event_seq))
                    .is_some();
                match row.object_kind.as_deref() {
                    Some("capture_receipt") => {
                        require_physical_row(
                            row,
                            ObjectFamily::Evidence,
                            "capture_receipt",
                            &value.execution_lane_id.to_string(),
                            &revision_id.to_string(),
                        )?;
                        duplicate_revision
                            || self
                                .capture_receipts
                                .insert(value.execution_lane_id, (value, row.source_event_seq))
                                .is_some()
                    }
                    Some("capture_receipt_revision") => {
                        require_physical_row(
                            row,
                            ObjectFamily::Evidence,
                            "capture_receipt_revision",
                            &revision_id.to_string(),
                            &revision_id.to_string(),
                        )?;
                        duplicate_revision
                    }
                    _ => return Err(StoreError::StoreCorrupt),
                }
            }
            JournalPayload::CaptureGapMarkerRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Evidence,
                    "capture_gap_marker",
                    &value.marker_id,
                    &format!("{}@{}", value.marker_id, value.reconciliation_revision),
                )?;
                self.capture_gaps
                    .insert(value.marker_id.clone(), (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::CaptureOutageIntervalRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Evidence,
                    "capture_outage_interval",
                    &value.capture_outage_interval_id.to_string(),
                    &format!(
                        "{}@{}",
                        value.capture_outage_interval_id, value.reconciliation_revision
                    ),
                )?;
                self.capture_outages
                    .insert(
                        value.capture_outage_interval_id,
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::SourceCloseReconciliation(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:reconciliation:{}", value.reconciliation_ref),
                )?;
                self.source_close_reconciliations
                    .insert(
                        value.reconciliation_ref.clone(),
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::RepositoryInstanceRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "repository",
                    &value.repository_id.to_string(),
                    &format!("{}@{}", value.repository_id, value.repository_revision),
                )?;
                self.repositories
                    .insert(value.repository_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorktreeInstanceRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "worktree",
                    &value.worktree_instance_id.to_string(),
                    &format!("{}@{}", value.worktree_instance_id, value.worktree_revision),
                )?;
                self.worktrees
                    .insert(value.worktree_instance_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorktreeSnapshotRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "worktree_snapshot",
                    &value.worktree_snapshot_id.to_string(),
                    &value.worktree_snapshot_id.to_string(),
                )?;
                self.worktree_snapshots
                    .insert(value.worktree_snapshot_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorktreeTransitionRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "worktree_transition",
                    &value.worktree_transition_id.to_string(),
                    &format!(
                        "{}@{}",
                        value.worktree_transition_id, value.transition_revision
                    ),
                )?;
                self.worktree_transitions
                    .insert(value.worktree_transition_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::IntegrationEventRecorded(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "integration_event",
                    &value.integration_event_id.to_string(),
                    &value.integration_event_id.to_string(),
                )?;
                self.integration_events
                    .insert(value.integration_event_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::RecoveryCaptureRequestRecorded(value) => {
                let value = *value;
                recovery::require_revision_row(
                    row,
                    "recovery_capture_request_revision",
                    &value.recovery_capture_request_id.to_string(),
                    &value.request_revision_id.to_string(),
                )?;
                recovery::record_request(
                    &mut self.recovery_requests,
                    &mut self.recovery_request_revisions,
                    value,
                    row.source_event_seq,
                    StoreError::StoreCorrupt,
                )?;
                false
            }
            JournalPayload::RecoveryBundleRecorded(value) => {
                recovery::require_revision_row(
                    row,
                    "recovery_bundle",
                    &value.recovery_bundle_id.to_string(),
                    &value.recovery_bundle_id.to_string(),
                )?;
                recovery::record_bundle(
                    &mut self.recovery_bundles,
                    *value,
                    row.source_event_seq,
                    StoreError::StoreCorrupt,
                )?;
                false
            }
            JournalPayload::RecoveryApplicationRecorded(value) => {
                let value = *value;
                recovery::require_revision_row(
                    row,
                    "recovery_application_revision",
                    &value.recovery_application_id.to_string(),
                    &value.revision_id.to_string(),
                )?;
                recovery::record_application(
                    &mut self.recovery_applications,
                    &mut self.recovery_application_revisions,
                    value,
                    row.source_event_seq,
                    StoreError::StoreCorrupt,
                )?;
                false
            }
            JournalPayload::ExperimentRunRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id = format!("object:work:experiment_run:{}", value.run_id);
                require_work_identity_row(
                    &normalized,
                    "experiment_run",
                    &value.run_id.to_string(),
                    &value.revision_id.to_string(),
                    None,
                    Some(&value.workstream_id.to_string()),
                    None,
                    None,
                    value.execution_status.as_str(),
                )?;
                self.experiment_run_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::ResultEvidenceRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id =
                    format!("object:work:result_evidence:{}", value.result_evidence_id);
                require_work_identity_row(
                    &normalized,
                    "result_evidence",
                    &value.result_evidence_id.to_string(),
                    &value.revision_id.to_string(),
                    None,
                    None,
                    None,
                    None,
                    value.completeness.as_str(),
                )?;
                self.result_evidence_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::WorkArtifactRecorded(value) => {
                let value = *value;
                let mut normalized = row.clone();
                normalized.row_id = format!("object:work:work_artifact:{}", value.work_artifact_id);
                require_work_identity_row(
                    &normalized,
                    "work_artifact",
                    &value.work_artifact_id.to_string(),
                    &value.revision.revision_id.to_string(),
                    value
                        .revision
                        .scope
                        .task_id()
                        .map(|id| id.to_string())
                        .as_deref(),
                    None,
                    value
                        .revision
                        .scope
                        .repository_id()
                        .map(|id| id.to_string())
                        .as_deref(),
                    value
                        .revision
                        .scope
                        .worktree_id()
                        .map(|id| id.to_string())
                        .as_deref(),
                    value.revision.payload_status.as_str(),
                )?;
                self.artifact_revisions
                    .insert(value.revision.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::AtomRecorded(value) => {
                let value = *value;
                require_semantic_atom_row(row, &value)?;
                self.atom_revisions
                    .insert(value.revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::RevisionProposalRecorded(value) => {
                let value = *value;
                require_semantic_proposal_row(row, &value)?;
                self.proposal_revisions
                    .insert(value.proposal_revision_id, (value, row.source_event_seq))
                    .is_some()
            }
            payload @ (JournalPayload::ProcedureRevisionRecorded(_)
            | JournalPayload::ProcedureStateRecorded(_)
            | JournalPayload::ProcedureUsageRecorded(_)
            | JournalPayload::ProcedureNegativeEvidenceRecorded(_)
            | JournalPayload::ProcedureNegativeReviewRecorded(_)) => {
                self.procedure.restore(payload, row.source_event_seq)?;
                false
            }
            payload @ (JournalPayload::ScenarioRecorded(_)
            | JournalPayload::CoreMembershipRecorded(_)
            | JournalPayload::GlobalSupportContractRecorded(_)
            | JournalPayload::GlobalSupportValidationRecorded(_)) => {
                self.s23.restore(payload, row.source_event_seq)?;
                false
            }
            payload @ (JournalPayload::SemanticDigestRecorded(_)
            | JournalPayload::SemanticDerivationRunRecorded(_)) => {
                self.synthesis.restore(payload, row.source_event_seq)?;
                false
            }
            JournalPayload::RecallLedgerRecorded(_) => return Err(StoreError::StoreCorrupt),
            JournalPayload::SessionImportEventRecorded(_) => {
                return Err(StoreError::StoreCorrupt);
            }
        };
        if duplicate {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    fn into_snapshot(self, frontier: u64) -> Result<ProjectionSnapshot, StoreError> {
        self.validate_evidence_relations()?;
        let mut rows = self.into_rows()?;
        rows.push(ObjectRow::checkpoint(frontier, PROJECTION_GENERATION));
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        Ok(ProjectionSnapshot { frontier, rows })
    }

    fn into_rows(self) -> Result<Vec<ObjectRow>, StoreError> {
        let mut rows = Vec::new();
        rows.extend(recall_projection::rows(&self.atoms, |atom| {
            self.s23.atom_support_eligible(atom.revision_id)
        })?);
        rows.extend(self.recall_ledger.clone().rows(PROJECTION_GENERATION)?);
        rows.extend(
            self.session_imports
                .values()
                .map(|value| crate::session_import::current_row(value, PROJECTION_GENERATION))
                .collect::<Result<Vec<_>, _>>()?,
        );
        rows.extend(synthesis::wiki_rows(
            &self.atoms,
            &self.proposals,
            &self.episodes,
            &self.synthesis,
            &self.s23,
        )?);
        rows.extend(self.procedure.rows(PROJECTION_GENERATION, &self.s23)?);
        rows.extend(self.procedure.effect_rows(
            &self.episode_revisions,
            &self.worktree_snapshots,
            &self.worktrees,
            &self.result_evidence_revisions,
            &self.artifact_revisions,
            PROJECTION_GENERATION,
        )?);
        rows.extend(self.s23.rows(&self.atom_revisions, PROJECTION_GENERATION)?);
        rows.extend(self.synthesis.rows()?);
        for (migration, (payload, seq)) in self.migrations {
            rows.push(runtime_row(
                format!("projection:migration:{migration}"),
                ObjectRowClass::Projection,
                &payload,
                seq,
            )?);
        }
        for (key, (value, seq)) in self.dirty {
            rows.push(runtime_row(
                format!("runtime:dirty:{key}"),
                ObjectRowClass::Runtime,
                &JournalPayload::DirtyTarget(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.outbox {
            rows.push(runtime_row(
                format!("runtime:outbox:{id}"),
                ObjectRowClass::Runtime,
                &JournalPayload::OutboxEnqueued(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.jobs {
            rows.push(runtime_row(
                format!("runtime:job:{id}"),
                ObjectRowClass::Runtime,
                &JournalPayload::JobState(value),
                seq,
            )?);
        }
        for (kind, (value, seq)) in self.watermarks {
            rows.push(runtime_row(
                format!("runtime:watermark:{kind}"),
                ObjectRowClass::Runtime,
                &JournalPayload::WatermarkAdvanced(value),
                seq,
            )?);
        }
        if let Some((payload, seq)) = self.config {
            rows.push(runtime_row(
                "runtime:config:current".into(),
                ObjectRowClass::Runtime,
                &payload,
                seq,
            )?);
        }
        for (event_id, (payload, seq)) in self.stale_audits {
            rows.push(runtime_row(
                format!("projection:audit:stale:{event_id}"),
                ObjectRowClass::Projection,
                &payload,
                seq,
            )?);
        }
        for (key, (value, seq)) in self.source_revisions {
            let fields = evidence_fields(
                format!("object:evidence:source_revision:{key}"),
                "source_revision",
                key,
                value.source_revision.as_str().to_owned(),
                None,
                None,
                None,
            );
            rows.push(evidence_object_row(
                fields,
                &JournalPayload::SourceRevisionRecorded(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.source_receipts {
            let fields = evidence_fields(
                format!("object:evidence:source_receipt:{id}"),
                "source_receipt",
                id.to_string(),
                id.to_string(),
                value.repository_instance_id.map(|value| value.to_string()),
                value.worktree_instance_id.map(|value| value.to_string()),
                value.task_id.map(|value| value.to_string()),
            );
            rows.push(evidence_object_row(
                fields,
                &JournalPayload::SourceReceiptRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.source_observations {
            let fields = evidence_fields(
                format!("object:evidence:source_observation:{id}"),
                "source_observation",
                id.to_string(),
                id.to_string(),
                None,
                None,
                None,
            );
            rows.push(evidence_object_row(
                fields,
                &JournalPayload::SourceObservationRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (key, (value, seq)) in self.source_watermarks {
            rows.push(runtime_row(
                format!("runtime:watermark:source:{key}"),
                ObjectRowClass::Runtime,
                &JournalPayload::SourceIngestWatermark(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.evidence_surfaces {
            rows.push(surface_row(id, value, seq)?);
        }
        for ((id, revision), (value, seq)) in self.host_occurrence_revisions {
            let mut row = physical_object_row(
                ObjectFamily::Evidence,
                "host_occurrence",
                id.to_string(),
                format!("{id}@{revision}"),
                &JournalPayload::HostOccurrenceNormalized(Box::new(value)),
                seq,
            )?;
            row.row_id = format!("object:evidence:host_occurrence:{id}@{revision}");
            rows.push(row);
        }
        for ((id, revision), (value, seq)) in self.operation_revisions {
            let mut row = physical_object_row(
                ObjectFamily::Work,
                "operation",
                id.to_string(),
                format!("{id}@{revision}"),
                &JournalPayload::OperationDerived(Box::new(value)),
                seq,
            )?;
            row.row_id = format!("object:work:operation:{id}@{revision}");
            rows.push(row);
        }
        for (id, (value, seq)) in self.scope_effects {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "scope_effect",
                id.to_string(),
                id.to_string(),
                &JournalPayload::ScopeEffectDerived(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.normalization_watermarks {
            rows.push(runtime_row(
                format!("runtime:watermark:normalization:{id}"),
                ObjectRowClass::Runtime,
                &JournalPayload::NormalizationWatermark(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.execution_lanes {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "execution_lane",
                id.to_string(),
                format!("{}@{}", id, value.lane_revision),
                &JournalPayload::ExecutionLaneRecorded(Box::new(value)),
                seq,
            )?);
        }
        let current_capture_revision_ids = self
            .capture_receipts
            .values()
            .map(|(value, _)| value.capture_receipt_revision_id)
            .collect::<BTreeSet<_>>();
        for (lane_id, (value, seq)) in self.capture_receipts {
            rows.push(physical_object_row(
                ObjectFamily::Evidence,
                "capture_receipt",
                lane_id.to_string(),
                value.capture_receipt_revision_id.to_string(),
                &JournalPayload::CaptureReceiptRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (revision_id, (value, seq)) in self.capture_receipt_revisions {
            if current_capture_revision_ids.contains(&revision_id) {
                continue;
            }
            rows.push(physical_object_row(
                ObjectFamily::Evidence,
                "capture_receipt_revision",
                revision_id.to_string(),
                revision_id.to_string(),
                &JournalPayload::CaptureReceiptRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (marker_id, (value, seq)) in self.capture_gaps {
            rows.push(physical_object_row(
                ObjectFamily::Evidence,
                "capture_gap_marker",
                marker_id.clone(),
                format!("{}@{}", marker_id, value.reconciliation_revision),
                &JournalPayload::CaptureGapMarkerRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.capture_outages {
            rows.push(physical_object_row(
                ObjectFamily::Evidence,
                "capture_outage_interval",
                id.to_string(),
                format!("{}@{}", id, value.reconciliation_revision),
                &JournalPayload::CaptureOutageIntervalRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (reference, (value, seq)) in self.source_close_reconciliations {
            rows.push(runtime_row(
                format!("runtime:reconciliation:{reference}"),
                ObjectRowClass::Runtime,
                &JournalPayload::SourceCloseReconciliation(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.repositories {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "repository",
                id.to_string(),
                format!("{}@{}", id, value.repository_revision),
                &JournalPayload::RepositoryInstanceRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.worktrees {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "worktree",
                id.to_string(),
                format!("{}@{}", id, value.worktree_revision),
                &JournalPayload::WorktreeInstanceRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.worktree_snapshots {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "worktree_snapshot",
                id.to_string(),
                id.to_string(),
                &JournalPayload::WorktreeSnapshotRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.worktree_transitions {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "worktree_transition",
                id.to_string(),
                format!("{}@{}", id, value.transition_revision),
                &JournalPayload::WorktreeTransitionRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.integration_events {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "integration_event",
                id.to_string(),
                id.to_string(),
                &JournalPayload::IntegrationEventRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.tasks {
            rows.push(work_identity_row(
                "task",
                id.to_string(),
                value.revision_id.to_string(),
                value.lifecycle.as_str(),
                Some(value.task_id.to_string()),
                None,
                None,
                None,
                &JournalPayload::TaskRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.workstreams {
            rows.push(work_identity_row(
                "workstream",
                id.to_string(),
                value.revision_id.to_string(),
                value.status.as_str(),
                Some(value.task_id.to_string()),
                Some(value.workstream_id.to_string()),
                value.repository_instance_id.map(|id| id.to_string()),
                value.active_worktree_instance_id.map(|id| id.to_string()),
                &JournalPayload::WorkstreamRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.work_bindings {
            rows.push(work_identity_row(
                "work_binding",
                id.to_string(),
                id.to_string(),
                value.assignment_status.as_str(),
                value.primary_binding.task_id.map(|id| id.to_string()),
                value.primary_binding.workstream_id.map(|id| id.to_string()),
                None,
                None,
                &JournalPayload::WorkBindingRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (_revision_id, (value, seq)) in self.attempt_revisions {
            let mut row = work_identity_row(
                "attempt",
                value.attempt_id.to_string(),
                value.revision_id.to_string(),
                value.lifecycle_status.as_str(),
                Some(value.task_id.to_string()),
                Some(value.workstream_id.to_string()),
                value.repository_instance_id.map(|id| id.to_string()),
                value.worktree_instance_ids.first().map(ToString::to_string),
                &JournalPayload::AttemptRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:attempt:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.competing_group_revisions {
            let mut row = work_identity_row(
                "competing_attempt_group",
                value.competing_group_id.to_string(),
                value.revision_id.to_string(),
                value.resolution_status.as_str(),
                Some(value.task_id.to_string()),
                value.origin_workstream_id.map(|id| id.to_string()),
                None,
                None,
                &JournalPayload::CompetingAttemptGroupRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:competing_attempt_group:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.operation_burst_revisions {
            let mut row = work_identity_row(
                "operation_burst",
                value.operation_burst_id.to_string(),
                value.revision_id.to_string(),
                value.lifecycle.as_str(),
                None,
                None,
                None,
                None,
                &JournalPayload::OperationBurstRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:operation_burst:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.episode_revisions {
            let mut row = work_identity_row(
                "work_episode",
                value.episode_id.to_string(),
                value.revision_id.to_string(),
                value.lifecycle_status.as_str(),
                Some(value.task_id.to_string()),
                Some(value.workstream_id.to_string()),
                value.repository_instance_id.map(|id| id.to_string()),
                value.worktree_instance_id.map(|id| id.to_string()),
                &JournalPayload::WorkEpisodeRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:work_episode:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (key, (value, seq)) in self.checkpoints {
            rows.push(work_identity_row(
                "work_checkpoint",
                key,
                value.episode_revision_id.to_string(),
                "derived",
                None,
                None,
                None,
                None,
                &JournalPayload::WorkCheckpointRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.corrections {
            rows.push(work_identity_row(
                "segmentation_correction",
                id.to_string(),
                id.to_string(),
                value.kind.as_str(),
                None,
                None,
                None,
                None,
                &JournalPayload::SegmentationCorrectionRecorded(Box::new(value)),
                seq,
            )?);
        }
        rows.extend(recovery::revision_rows(
            self.recovery_request_revisions,
            self.recovery_bundles,
            self.recovery_application_revisions,
        )?);
        for (_revision_id, (value, seq)) in self.experiment_run_revisions {
            let mut row = work_identity_row(
                "experiment_run",
                value.run_id.to_string(),
                value.revision_id.to_string(),
                value.execution_status.as_str(),
                None,
                Some(value.workstream_id.to_string()),
                None,
                None,
                &JournalPayload::ExperimentRunRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:experiment_run:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.result_evidence_revisions {
            let mut row = work_identity_row(
                "result_evidence",
                value.result_evidence_id.to_string(),
                value.revision_id.to_string(),
                value.completeness.as_str(),
                None,
                None,
                None,
                None,
                &JournalPayload::ResultEvidenceRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:result_evidence:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.artifact_revisions {
            let mut row = work_identity_row(
                "work_artifact",
                value.work_artifact_id.to_string(),
                value.revision.revision_id.to_string(),
                value.revision.payload_status.as_str(),
                value.revision.scope.task_id().map(|id| id.to_string()),
                None,
                value
                    .revision
                    .scope
                    .repository_id()
                    .map(|id| id.to_string()),
                value.revision.scope.worktree_id().map(|id| id.to_string()),
                &JournalPayload::WorkArtifactRecorded(Box::new(value)),
                seq,
            )?;
            row.row_id = format!(
                "object:work:work_artifact:{}",
                row.current_revision_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
            );
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.atom_revisions {
            let mut row = semantic_atom_row(
                &value,
                &JournalPayload::AtomRecorded(Box::new(value.clone())),
                seq,
            )?;
            row.support_state = self
                .s23
                .atom_support_state(value.revision_id)
                .map(str::to_owned);
            rows.push(row);
        }
        for (_revision_id, (value, seq)) in self.proposal_revisions {
            rows.push(semantic_proposal_row(
                &value,
                &JournalPayload::RevisionProposalRecorded(Box::new(value.clone())),
                seq,
            )?);
        }
        Ok(rows)
    }

    fn validate_evidence_relations(&self) -> Result<(), StoreError> {
        self.s23.validate(
            &self.atom_revisions,
            &self.proposal_revisions,
            &self.procedure,
        )?;
        let source_ranges = current_source_ranges(&self.source_receipts)?;
        validate_capture_relations(
            &self.execution_lanes,
            &self.capture_receipts,
            &self.capture_gaps,
            &self.capture_outages,
            &self.source_close_reconciliations,
            &source_ranges,
            &self.operations.keys().copied().collect(),
        )?;
        for (observation, _) in self.source_observations.values() {
            let receipt = self
                .source_receipts
                .get(&observation.source_receipt_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            if receipt.0.source_observation_id != observation.source_observation_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (surface, _) in self.evidence_surfaces.values() {
            if !self
                .source_observations
                .contains_key(&surface.source_observation_revision_ref)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (occurrence, _) in self.host_occurrences.values() {
            if occurrence
                .source_observation_refs
                .iter()
                .any(|id| !self.source_observations.contains_key(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (operation, _) in self.operations.values() {
            let Some((occurrence, _)) = self.host_occurrences.get(&operation.host_occurrence_id)
            else {
                return Err(StoreError::StoreCorrupt);
            };
            if operation
                .input_source_observation_refs
                .iter()
                .chain(&operation.result_source_observation_refs)
                .any(|id| !occurrence.source_observation_refs.contains(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
            let actual = self
                .scope_effects
                .values()
                .filter(|(effect, _)| effect.operation_id == operation.operation_id)
                .map(|(effect, _)| effect.scope_effect_id)
                .collect::<std::collections::BTreeSet<_>>();
            if actual != operation.scope_effect_ids.iter().copied().collect() {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (effect, _) in self.scope_effects.values() {
            let Some((operation, _)) = self.operations.get(&effect.operation_id) else {
                return Err(StoreError::StoreCorrupt);
            };
            let occurrence = self
                .host_occurrences
                .get(&operation.host_occurrence_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if effect
                .evidence_refs
                .iter()
                .any(|id| !occurrence.0.source_observation_refs.contains(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for watermark in self.normalization_watermarks.keys() {
            if !self.source_observations.contains_key(watermark) {
                return Err(StoreError::StoreCorrupt);
            }
        }
        crate::repository::validate_repository_relations(
            &self.repositories,
            &self.worktrees,
            &self.worktree_snapshots,
            &self.worktree_transitions,
            &self.integration_events,
        )?;
        validate_work_identity_relations(
            &self.tasks,
            &self.workstreams,
            &self.repositories,
            &self.worktrees,
        )?;
        validate_work_binding_relations(
            &self.work_bindings,
            &self.operations,
            &self.scope_effects,
            &self.tasks,
            &self.workstreams,
            &self.attempts,
            &self.competing_groups,
            &self.episodes,
            &self.experiment_runs,
        )?;
        validate_attempt_relations(
            &self.attempts,
            &self.attempt_revisions,
            &self.competing_groups,
            &self.tasks,
            &self.workstreams,
            &self.execution_lanes,
            &self.worktree_snapshots,
            &self.worktree_transitions,
            &self.integration_events,
            &self.work_bindings,
        )?;
        validate_episode_relations(
            &self.episodes,
            &self.episode_revisions,
            &self.checkpoints,
            &self.corrections,
            &self.tasks,
            &self.workstreams,
            &self.attempts,
            &self.attempt_revisions,
            &self.competing_groups,
            &self.work_bindings,
            &self.operation_bursts,
            &self.operation_revisions,
            &self.host_occurrences,
            &self.source_observations,
            &self.scope_effects,
            &self.execution_lanes,
            &self.capture_receipt_revisions,
            &self.capture_gaps,
            &self.capture_outages,
            &self.worktree_snapshots,
            &self.worktree_transitions,
            &self.integration_events,
        )?;
        recovery::validate_relations(recovery::RecoveryRelationInputs {
            requests: &self.recovery_requests,
            bundles: &self.recovery_bundles,
            applications: &self.recovery_applications,
            application_revisions: &self.recovery_application_revisions,
            worktrees: &self.worktrees,
            snapshots: &self.worktree_snapshots,
            operation_revisions: &self.operation_revisions,
            execution_lane_revisions: &self.execution_lane_revisions,
            capture_receipt_revisions: &self.capture_receipt_revisions,
            scope_effects: &self.scope_effects,
            source_observations: &self.source_observations,
            source_receipts: &self.source_receipts,
            attempt_revisions: &self.attempt_revisions,
            competing_group_revisions: &self.competing_group_revisions,
        })?;
        autoresearch::validate_relations(autoresearch::AutoresearchRelationInputs {
            runs: &self.experiment_runs,
            run_revisions: &self.experiment_run_revisions,
            results: &self.result_evidence,
            artifacts: &self.work_artifacts,
            attempts: &self.attempts,
            tasks: &self.tasks,
            workstreams: &self.workstreams,
            operations: &self.operations,
            episodes: &self.episodes,
            snapshots: &self.worktree_snapshots,
            repositories: &self.repositories,
            worktrees: &self.worktrees,
            source_receipts: &self.source_receipts,
            source_observations: &self.source_observations,
        })?;
        semantic::validate_relations(semantic::SemanticRelationInputs {
            atom_revisions: &self.atom_revisions,
            proposal_revisions: &self.proposal_revisions,
            source_observations: &self.source_observations,
            source_receipts: &self.source_receipts,
            tasks: &self.tasks,
            repositories: &self.repositories,
            worktrees: &self.worktrees,
            results: &self.result_evidence,
            artifacts: &self.work_artifacts,
            procedure: &self.procedure,
            s23: &self.s23,
            semantic_digests: self.synthesis.digests(),
        })?;
        let admission = self.admission_state(0)?;
        admission.validate_procedure_relations()?;
        validate_recall_ledger_relations(self)?;
        Ok(())
    }

    fn admission_state(&self, frontier: u64) -> Result<JournalAdmissionState, StoreError> {
        Ok(JournalAdmissionState {
            session_imports: self.session_imports.clone(),
            frontier,
            source_ranges: current_source_ranges(&self.source_receipts)?,
            source_observations: self.source_observations.clone(),
            source_receipts: self.source_receipts.clone(),
            evidence_surfaces: self.evidence_surfaces.clone(),
            host_occurrences: self.host_occurrences.clone(),
            host_occurrence_revisions: self.host_occurrence_revisions.clone(),
            operations: self.operations.clone(),
            operation_revisions: self.operation_revisions.clone(),
            scope_effects: self.scope_effects.clone(),
            execution_lanes: self.execution_lanes.clone(),
            execution_lane_revisions: self.execution_lane_revisions.clone(),
            capture_receipts: self.capture_receipts.clone(),
            capture_receipt_revisions: self.capture_receipt_revisions.clone(),
            capture_gaps: self.capture_gaps.clone(),
            capture_outages: self.capture_outages.clone(),
            source_close_reconciliations: self.source_close_reconciliations.clone(),
            repositories: self.repositories.clone(),
            worktrees: self.worktrees.clone(),
            worktree_snapshots: self.worktree_snapshots.clone(),
            worktree_transitions: self.worktree_transitions.clone(),
            integration_events: self.integration_events.clone(),
            tasks: self.tasks.clone(),
            workstreams: self.workstreams.clone(),
            work_bindings: self.work_bindings.clone(),
            attempts: self.attempts.clone(),
            competing_groups: self.competing_groups.clone(),
            attempt_revisions: self.attempt_revisions.clone(),
            competing_group_revisions: self.competing_group_revisions.clone(),
            operation_bursts: self.operation_bursts.clone(),
            operation_burst_revisions: self.operation_burst_revisions.clone(),
            episodes: self.episodes.clone(),
            episode_revisions: self.episode_revisions.clone(),
            checkpoints: self.checkpoints.clone(),
            corrections: self.corrections.clone(),
            recovery_requests: self.recovery_requests.clone(),
            recovery_request_revisions: self.recovery_request_revisions.clone(),
            recovery_bundles: self.recovery_bundles.clone(),
            recovery_applications: self.recovery_applications.clone(),
            recovery_application_revisions: self.recovery_application_revisions.clone(),
            experiment_runs: self.experiment_runs.clone(),
            experiment_run_revisions: self.experiment_run_revisions.clone(),
            result_evidence: self.result_evidence.clone(),
            result_evidence_revisions: self.result_evidence_revisions.clone(),
            work_artifacts: self.work_artifacts.clone(),
            artifact_revisions: self.artifact_revisions.clone(),
            atoms: self.atoms.clone(),
            atom_revisions: self.atom_revisions.clone(),
            proposals: self.proposals.clone(),
            proposal_revisions: self.proposal_revisions.clone(),
            recall_ledger: self.recall_ledger.clone(),
            s23: self.s23.clone(),
            procedure: self.procedure.clone(),
            synthesis: self.synthesis.clone(),
            jobs: self
                .jobs
                .iter()
                .map(|(id, (job, _))| (*id, job.clone()))
                .collect(),
        })
    }
}

fn require_row(
    row: &ObjectRow,
    expected_class: ObjectRowClass,
    expected_id: &str,
) -> Result<(), StoreError> {
    if row.row_class != Some(expected_class) || row.row_id != expected_id {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

struct EvidenceRowFields {
    row_id: String,
    object_kind: String,
    object_id: String,
    revision_id: String,
    repository_id: Option<String>,
    worktree_id: Option<String>,
    task_id: Option<String>,
}

fn evidence_fields(
    row_id: String,
    object_kind: &str,
    object_id: String,
    revision_id: String,
    repository_id: Option<String>,
    worktree_id: Option<String>,
    task_id: Option<String>,
) -> EvidenceRowFields {
    EvidenceRowFields {
        row_id,
        object_kind: object_kind.to_owned(),
        object_id,
        revision_id,
        repository_id,
        worktree_id,
        task_id,
    }
}

fn require_evidence_object_row(
    row: &ObjectRow,
    fields: &EvidenceRowFields,
) -> Result<(), StoreError> {
    if row.row_id != fields.row_id
        || row.row_class != Some(ObjectRowClass::Object)
        || row.object_family != Some(ObjectFamily::Evidence)
        || row.object_kind.as_deref() != Some(fields.object_kind.as_str())
        || row.object_id.as_deref() != Some(fields.object_id.as_str())
        || row.current_revision_id.as_deref() != Some(fields.revision_id.as_str())
        || row.lifecycle.as_deref() != Some("immutable")
        || row.authority.as_deref() != Some("none")
        || row.repository_id != fields.repository_id
        || row.worktree_id != fields.worktree_id
        || row.task_id != fields.task_id
        || row.project_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn require_physical_row(
    row: &ObjectRow,
    family: ObjectFamily,
    kind: &str,
    object_id: &str,
    revision_id: &str,
) -> Result<(), StoreError> {
    if row.row_id != format!("object:{}:{kind}:{object_id}", family.as_str())
        || row.row_class != Some(ObjectRowClass::Object)
        || row.object_family != Some(family)
        || row.object_kind.as_deref() != Some(kind)
        || row.object_id.as_deref() != Some(object_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
        || row.lifecycle.as_deref() != Some("immutable")
        || row.authority.as_deref() != Some("none")
        || row.project_id.is_some()
        || row.repository_id.is_some()
        || row.worktree_id.is_some()
        || row.task_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn require_work_identity_row(
    row: &ObjectRow,
    kind: &str,
    object_id: &str,
    revision_id: &str,
    task_id: Option<&str>,
    workstream_id: Option<&str>,
    repository_id: Option<&str>,
    worktree_id: Option<&str>,
    lifecycle: &str,
) -> Result<(), StoreError> {
    if row.row_id != format!("object:work:{kind}:{object_id}")
        || row.row_class != Some(ObjectRowClass::Object)
        || row.object_family != Some(ObjectFamily::Work)
        || row.object_kind.as_deref() != Some(kind)
        || row.object_id.as_deref() != Some(object_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
        || row.lifecycle.as_deref() != Some(lifecycle)
        || row.authority.as_deref() != Some("none")
        || row.task_id.as_deref() != task_id
        || row.workstream_id.as_deref() != workstream_id
        || row.repository_id.as_deref() != repository_id
        || row.worktree_id.as_deref() != worktree_id
        || row.project_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn require_surface_row(row: &ObjectRow, surface: &EvidenceSurface) -> Result<(), StoreError> {
    let revision_id = surface.source_observation_revision_ref.to_string();
    if row.row_id
        != format!(
            "projection:evidence_surface:{}",
            surface.source_observation_revision_ref
        )
        || row.row_class != Some(ObjectRowClass::Projection)
        || row.object_family.is_some()
        || row.object_kind.as_deref() != Some("evidence_surface")
        || row.object_id.is_some()
        || row.current_revision_id.as_deref() != Some(revision_id.as_str())
        || row.authority.as_deref() != Some("none")
        || row.repository_id
            != surface
                .repository_instance_id
                .map(|value| value.to_string())
        || row.worktree_id != surface.worktree_instance_id.map(|value| value.to_string())
        || row.task_id != surface.task_id.map(|value| value.to_string())
        || row.project_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn valid_event_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn runtime_row(
    row_id: String,
    row_class: ObjectRowClass,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id,
        row_kind: ObjectRowKind::Data,
        row_class: Some(row_class),
        object_family: None,
        object_kind: None,
        object_id: None,
        current_revision_id: None,
        lifecycle: None,
        epistemic: None,
        authority: None,
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn evidence_object_row(
    fields: EvidenceRowFields,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: fields.row_id,
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::Evidence),
        object_kind: Some(fields.object_kind),
        object_id: Some(fields.object_id),
        current_revision_id: Some(fields.revision_id),
        lifecycle: Some("immutable".into()),
        epistemic: Some("observed".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: fields.repository_id,
        worktree_id: fields.worktree_id,
        task_id: fields.task_id,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn physical_object_row(
    family: ObjectFamily,
    kind: &str,
    object_id: String,
    revision_id: String,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("object:{}:{kind}:{object_id}", family.as_str()),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(family),
        object_kind: Some(kind.into()),
        object_id: Some(object_id),
        current_revision_id: Some(revision_id),
        lifecycle: Some("immutable".into()),
        epistemic: Some("observed".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn semantic_atom_row(
    atom: &Atom,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("object:atom:atom_revision:{}", atom.revision_id),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::Atom),
        object_kind: Some("atom_revision".into()),
        object_id: Some(atom.atom_id.to_string()),
        current_revision_id: Some(atom.revision_id.to_string()),
        lifecycle: Some(atom.lifecycle_status.as_str().into()),
        epistemic: Some(atom.epistemic_status.as_str().into()),
        authority: Some(atom.authority.as_str().into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: atom.scope.repository_id().map(|id| id.to_string()),
        worktree_id: atom.scope.worktree_id().map(|id| id.to_string()),
        task_id: atom.scope.task_id().map(|id| id.to_string()),
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn semantic_proposal_row(
    proposal: &RevisionProposal,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!(
            "object:revision_proposal:revision_proposal_revision:{}",
            proposal.proposal_revision_id
        ),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::RevisionProposal),
        object_kind: Some("revision_proposal_revision".into()),
        object_id: Some(proposal.proposal_id.to_string()),
        current_revision_id: Some(proposal.proposal_revision_id.to_string()),
        lifecycle: Some(proposal.status.as_str().into()),
        epistemic: Some("not_applicable".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn require_semantic_atom_row(row: &ObjectRow, atom: &Atom) -> Result<(), StoreError> {
    let mut expected = semantic_atom_row(
        atom,
        &JournalPayload::AtomRecorded(Box::new(atom.clone())),
        row.source_event_seq,
    )?;
    if row.support_state.as_deref().is_some_and(|value| {
        matches!(
            value,
            "valid" | "revalidation_pending" | "insufficient" | "invalidated"
        )
    }) {
        expected.support_state = row.support_state.clone();
    }
    if row == &expected {
        Ok(())
    } else {
        Err(StoreError::StoreCorrupt)
    }
}

fn require_semantic_proposal_row(
    row: &ObjectRow,
    proposal: &RevisionProposal,
) -> Result<(), StoreError> {
    let expected = semantic_proposal_row(
        proposal,
        &JournalPayload::RevisionProposalRecorded(Box::new(proposal.clone())),
        row.source_event_seq,
    )?;
    if row == &expected {
        Ok(())
    } else {
        Err(StoreError::StoreCorrupt)
    }
}

#[allow(clippy::too_many_arguments)]
fn work_identity_row(
    kind: &str,
    object_id: String,
    revision_id: String,
    lifecycle: &str,
    task_id: Option<String>,
    workstream_id: Option<String>,
    repository_id: Option<String>,
    worktree_id: Option<String>,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("object:work:{kind}:{object_id}"),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::Work),
        object_kind: Some(kind.into()),
        object_id: Some(object_id),
        current_revision_id: Some(revision_id),
        lifecycle: Some(lifecycle.into()),
        epistemic: Some("current".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id,
        worktree_id,
        task_id,
        workstream_id,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn surface_row(
    id: SourceObservationId,
    surface: EvidenceSurface,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("projection:evidence_surface:{id}"),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some("evidence_surface".into()),
        object_id: None,
        current_revision_id: Some(id.to_string()),
        lifecycle: None,
        epistemic: Some("evidence".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: surface
            .repository_instance_id
            .map(|value| value.to_string()),
        worktree_id: surface.worktree_instance_id.map(|value| value.to_string()),
        task_id: surface.task_id.map(|value| value.to_string()),
        workstream_id: None,
        session_id: None,
        payload_json: Some(
            JournalPayload::EvidenceSurfaceRecorded(Box::new(surface)).canonical_json()?,
        ),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn source_revision_key(value: &SourceRevisionRecorded) -> String {
    format!(
        "{}:{}{}:{}",
        value.source_instance_id.as_str().len(),
        value.source_instance_id.as_str(),
        value.source_revision.as_str().len(),
        value.source_revision.as_str()
    )
}

#[derive(Clone)]
pub struct ProjectionWorker {
    journal: Table,
    objects: Table,
}

impl ProjectionWorker {
    pub(crate) fn new(journal: Table, objects: Table) -> Self {
        Self { journal, objects }
    }

    pub async fn catch_up(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.catch_up_inner(false).await
    }

    pub async fn reconciliation_frontier(
        &self,
        limit: usize,
    ) -> Result<ReconciliationFrontier, StoreError> {
        self.catch_up().await?.reconciliation_frontier(limit)
    }

    pub async fn reconciliation_artifact_context(
        &self,
        descriptors: &[ReconciliationArtifactDescriptor],
        limit: usize,
    ) -> Result<ReconciliationArtifactFrontier, StoreError> {
        self.catch_up()
            .await?
            .reconciliation_artifact_context(descriptors, limit)
    }

    async fn catch_up_inner(
        &self,
        inject_before_commit_failure: bool,
    ) -> Result<ProjectionSnapshot, StoreError> {
        let current = validate_objects_table(&self.objects).await?;
        let checkpoint = current
            .iter()
            .find(|row| row.row_id == OBJECTS_CHECKPOINT_ID)
            .ok_or(StoreError::StoreCorrupt)?;
        let checkpoint_frontier = checkpoint.source_event_seq;
        let journal_frontier = read_journal_frontier(&self.journal).await?;
        if checkpoint.source_event_seq > journal_frontier {
            return Err(StoreError::StoreCorrupt);
        }
        if checkpoint_frontier == 0 && current.len() == 1 && journal_frontier > 0 {
            let expected = self.full_snapshot().await?;
            if expected.frontier != journal_frontier {
                return Err(StoreError::StoreCorrupt);
            }
            if inject_before_commit_failure {
                return Err(StoreError::Projection);
            }
            self.commit_rows(&expected.rows, true, true, true, true)
                .await?;
            let persisted = validate_objects_table(&self.objects).await?;
            if persisted != expected.rows {
                return Err(StoreError::Projection);
            }
            return Ok(expected);
        }
        let mut state = ReducerState::from_current_rows(&current, checkpoint_frontier)?;
        let delta = read_journal_after(&self.journal, checkpoint_frontier).await?;
        validate_delta(checkpoint_frontier, journal_frontier, &delta)?;
        if delta.is_empty() {
            return Ok(ProjectionSnapshot {
                frontier: checkpoint_frontier,
                rows: current,
            });
        }
        let reconcile_core = delta.iter().any(|row| {
            matches!(
                row.event_type.as_str(),
                ATOM_RECORDED_EVENT_TYPE
                    | "core_membership_recorded_v1"
                    | "global_support_contract_recorded_v1"
                    | "global_support_validation_recorded_v1"
            )
        });
        let reconcile_recall = reconcile_core;
        let reconcile_wiki = reconcile_core;
        let reconcile_procedure_effect = delta.iter().any(|row| {
            matches!(
                row.event_type.as_str(),
                "procedure_usage_recorded_v1"
                    | "procedure_negative_evidence_recorded_v1"
                    | "procedure_negative_review_recorded_v1"
                    | "worktree_snapshot_recorded_v1"
            )
        });
        let mut admission = state.admission_state(checkpoint_frontier)?;
        for batch in ordered_command_batches(&delta)? {
            admission = admission.apply_row_batch(&batch)?;
            for row in &batch {
                apply_event(&mut state, row, &batch)?;
            }
            state.validate_evidence_relations()?;
        }
        let expected = state.into_snapshot(journal_frontier)?;
        let current_by_id = current
            .iter()
            .map(|row| (row.row_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let changed = incremental_changed_rows(
            &expected,
            &current_by_id,
            reconcile_recall,
            reconcile_core,
            reconcile_wiki,
            reconcile_procedure_effect,
        );
        if inject_before_commit_failure {
            return Err(StoreError::Projection);
        }
        self.commit_rows(
            &changed,
            reconcile_recall,
            reconcile_core,
            reconcile_wiki,
            reconcile_procedure_effect,
        )
        .await?;
        let persisted = validate_objects_table(&self.objects).await?;
        let persisted_snapshot = ProjectionSnapshot {
            frontier: expected.frontier,
            rows: persisted,
        };
        if persisted_snapshot.rows != expected.rows {
            return Err(StoreError::Projection);
        }
        Ok(persisted_snapshot)
    }

    #[cfg(test)]
    async fn catch_up_with_commit_fault(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.catch_up_inner(true).await
    }

    pub async fn full_snapshot(&self) -> Result<ProjectionSnapshot, StoreError> {
        reduce_journal(&read_all_journal_rows(&self.journal).await?)
    }

    async fn commit_rows(
        &self,
        rows: &[ObjectRow],
        reconcile_recall: bool,
        reconcile_core: bool,
        reconcile_wiki: bool,
        reconcile_procedure_effect: bool,
    ) -> Result<(), StoreError> {
        let batch = objects_batch(rows)?;
        let reader: Box<dyn arrow_array::RecordBatchReader + Send> = Box::new(
            RecordBatchIterator::new(vec![Ok(batch)], crate::objects::objects_schema()),
        );
        let mut merge = self.objects.merge_insert(&["row_id"]);
        merge.when_matched_update_all(None);
        merge.when_not_matched_insert_all();
        if reconcile_recall || reconcile_core || reconcile_wiki || reconcile_procedure_effect {
            let mut predicates = Vec::new();
            if reconcile_recall {
                predicates.push(format!(
                    "object_kind = '{}'",
                    recall_projection::RECALL_TRIGGER_INDEX_KIND
                ));
            }
            if reconcile_core {
                predicates.push(format!("object_kind = '{}'", s23::CORE_PROJECTION_KIND));
            }
            if reconcile_wiki {
                predicates.push(format!(
                    "object_kind = '{}'",
                    synthesis::WIKI_PROJECTION_KIND
                ));
            }
            if reconcile_procedure_effect {
                predicates.push("object_kind = 'procedure_context_effect'".into());
            }
            merge.when_not_matched_by_source_delete(Some(predicates.join(" OR ")));
        }
        merge
            .execute(reader)
            .await
            .map_err(|_| StoreError::Projection)?;
        Ok(())
    }
}

fn incremental_changed_rows(
    expected: &ProjectionSnapshot,
    current_by_id: &BTreeMap<&str, &ObjectRow>,
    reconcile_recall: bool,
    reconcile_core: bool,
    reconcile_wiki: bool,
    reconcile_procedure_effect: bool,
) -> Vec<ObjectRow> {
    expected
        .rows
        .iter()
        .filter(|row| {
            row.row_id == OBJECTS_CHECKPOINT_ID
                || reconcile_recall
                    && row.object_kind.as_deref()
                        == Some(recall_projection::RECALL_TRIGGER_INDEX_KIND)
                || reconcile_core && row.object_kind.as_deref() == Some(s23::CORE_PROJECTION_KIND)
                || reconcile_wiki
                    && row.object_kind.as_deref() == Some(synthesis::WIKI_PROJECTION_KIND)
                || reconcile_procedure_effect
                    && row.object_kind.as_deref() == Some("procedure_context_effect")
                || current_by_id.get(row.row_id.as_str()).copied() != Some(*row)
        })
        .cloned()
        .collect()
}

pub(crate) fn validate_delta(
    checkpoint_frontier: u64,
    journal_frontier: u64,
    rows: &[JournalRow],
) -> Result<(), StoreError> {
    if rows.is_empty() {
        return if checkpoint_frontier == journal_frontier {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    if checkpoint_frontier >= journal_frontier
        || rows
            .first()
            .is_none_or(|row| row.seq <= checkpoint_frontier)
        || rows.last().is_none_or(|row| row.seq != journal_frontier)
        || rows.windows(2).any(|pair| pair[0].seq >= pair[1].seq)
    {
        return Err(StoreError::StoreCorrupt);
    }
    validate_journal_rows(rows)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::{
        evidence::{
            CaptureGapMarkerEvidence, CaptureOutageInterval, CaptureOutagePositiveSource,
            CorrelationStrength, NormalizationState, OperationKind, PairingState,
            ReconciliationProvenance, SourceInstanceId, SourceRevision,
        },
        ids::{
            AttemptId, CaptureOutageIntervalId, CasId, CommandId, CompetingAttemptGroupId,
            ExecutionLaneId, ExperimentRunId, HostOccurrenceId, IntegrationEventId, JobId,
            OperationId, ResultEvidenceId, SourceObservationId, SourceReceiptId, TaskId,
            WorkstreamId, WorktreeId, WorktreeSnapshotId,
        },
        repository::{IntegrationKind, LineageAssessment},
        semantic::{MetricValue, ParserReceipt, VerifierReceipt},
        work::{
            AdmissionFailureObservability, AttemptAdoptionStatus, AttemptBindingStatus,
            AttemptExecutionStatus, AttemptLifecycleStatus, AttemptOutcomeState,
            AttemptVerification, ComparisonExecutionBinding, CompetingConflictKind,
            CompetingResolutionStatus, ContractField, LaneLifecycleEvidence, LivenessState,
            MetricDirection, MultiCasMetricPolicy, PrimaryWorkBinding, RunContractValidity,
            RunExecutionStatus, RunObservability, RunOrigin, SeedPolicy, StrategyContract,
            VariableDeclaration,
        },
    };

    use super::*;
    use crate::{
        command::{
            DirtyTargetKind, JobBudget, JobLease, JobTerminalAudit, JobTerminalOutcome,
            JobTerminalReason, JournalCommand, JournalEventDraft, MigrationApplied,
            PreparedCommand, SourceCloseRange, prepare_command,
        },
        journal::rows_for_append,
        objects::read_object_rows,
        writer::JournalWriter,
    };

    #[test]
    fn session_prefix_digest_is_required_only_for_codex_sources() {
        let codex = SourceIngestWatermark {
            source_instance_id: SourceInstanceId::parse("codex-session:session-a").unwrap(),
            source_revision: SourceRevision::parse("revision-a").unwrap(),
            source_sequence: 1,
            confirmed_prefix_digest: None,
        };
        assert_eq!(
            validate_confirmed_session_prefix(&codex),
            Err(StoreError::StoreCorrupt)
        );
        let ordinary = SourceIngestWatermark {
            source_instance_id: SourceInstanceId::parse("ordinary-source").unwrap(),
            ..codex
        };
        assert_eq!(validate_confirmed_session_prefix(&ordinary), Ok(false));
        let forged_ordinary = SourceIngestWatermark {
            confirmed_prefix_digest: Some("1".repeat(64)),
            ..ordinary
        };
        assert_eq!(
            validate_confirmed_session_prefix(&forged_ordinary),
            Err(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn selected_competing_boundary_requires_precommand_exact_typed_cohort() {
        let group_id = CompetingAttemptGroupId::new_v7();
        let attempt_id = AttemptId::new_v7();
        let integration_id = IntegrationEventId::new_v7();
        let run_id = ExperimentRunId::new_v7();
        let run_revision_id = RevisionId::new_v7();
        let result_id = ResultEvidenceId::new_v7();
        let result_revision_id = RevisionId::new_v7();
        let workstream_id = WorkstreamId::new_v7();
        let mut attempt = Attempt {
            attempt_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            task_id: TaskId::new_v7(),
            workstream_id,
            episode_id: None,
            repository_instance_id: None,
            worktree_instance_ids: Vec::new(),
            execution_lane_ids: Vec::new(),
            competing_group_ids: vec![group_id],
            experiment_run_ids: Vec::new(),
            execution_status: AttemptExecutionStatus::Proposed,
            adoption_status: AttemptAdoptionStatus::Integrated,
            verification: AttemptVerification::Passed,
            lifecycle_status: AttemptLifecycleStatus::Active,
            strategy_contract: StrategyContract {
                hypothesis: "typed cohort".into(),
                intervention: "select winner".into(),
                intervention_family: "test".into(),
                search_policy_ref: None,
                objective_ref: None,
                expected_effect: "selected".into(),
                target_refs: vec!["target:test".into()],
                acceptance_boundary_ref: "acceptance:test".into(),
            },
            strategy_contract_fingerprint: [0; 32],
            resumes_from_attempt_id: None,
            composed_from_attempt_ids: Vec::new(),
            resume_event_refs: Vec::new(),
            resume_state_assessment: None,
            resume_source_snapshot_id: None,
            resume_target_snapshot_id: None,
            worktree_transition_refs: Vec::new(),
            integration_event_refs: vec![integration_id],
            recovery_bundle_refs: Vec::new(),
            recovery_application_refs: Vec::new(),
            work_binding_revision_refs: Vec::new(),
            local_outcome_refs: Vec::new(),
            parent_verification_refs: vec![result_id.to_string()],
            outcome_refs: Vec::new(),
            outcome_state: AttemptOutcomeState::Unknown,
            interruption_refs: Vec::new(),
            interruption_reason: None,
            explicit_abandon_refs: Vec::new(),
            supersede_evidence_refs: Vec::new(),
            failure_signature: None,
            source_watermark: 1,
        };
        attempt.strategy_contract_fingerprint = attempt.strategy_contract.fingerprint().unwrap();
        attempt.validate().unwrap();
        let strategy_fingerprint = attempt.strategy_contract_fingerprint;
        let integration = IntegrationEvent {
            integration_event_id: integration_id,
            repository_instance_id: RepositoryId::new_v7(),
            source_worktree_instance_id: WorktreeId::new_v7(),
            source_snapshot_id: WorktreeSnapshotId::new_v7(),
            destination_worktree_instance_id: WorktreeId::new_v7(),
            destination_snapshot_id: WorktreeSnapshotId::new_v7(),
            kind: IntegrationKind::ManualPatch,
            commit_refs: Vec::new(),
            patch_equivalence_refs: vec!["patch:test".into()],
            conflict_resolution_detected: false,
            integrated_attempt_ids: vec![attempt_id],
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec!["integration:test".into()],
            assessment: LineageAssessment::Proven,
        };
        integration.validate().unwrap();
        let source_receipt_id = SourceReceiptId::from_digest([1; 32]);
        let terminal_receipt_id = SourceReceiptId::from_digest([2; 32]);
        let declaration_revision_id = RevisionId::new_v7();
        let mut run = ExperimentRun {
            run_id,
            revision_id: run_revision_id,
            parent_revision_id: Some(declaration_revision_id),
            workstream_id,
            attempt_id: Some(attempt_id),
            attempt_binding_status: AttemptBindingStatus::Resolved,
            strategy_contract_fingerprint: strategy_fingerprint,
            origin: RunOrigin::Local,
            external_system_id: None,
            external_run_key: None,
            source_receipt_refs: vec![source_receipt_id],
            observability: RunObservability::Full,
            execution_status: RunExecutionStatus::Completed,
            contract_validity: RunContractValidity::Valid,
            experiment_contract_fingerprint: [0; 32],
            code_snapshot_id: WorktreeSnapshotId::new_v7(),
            data_fingerprint: "data:test".into(),
            normalized_config: Vec::<ContractField>::new(),
            variable_declaration: VariableDeclaration::default(),
            comparison_key: [0; 32],
            seed_policy: SeedPolicy::Unspecified,
            seed_values: Vec::new(),
            nondeterministic: false,
            metric_definition: "score".into(),
            metric_extractor_version: "test-v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: "environment:test".into(),
            comparison_execution_binding: Some(ComparisonExecutionBinding {
                binding_version: 1,
                toolchain_revision: "rust-1.97.1".into(),
                model_revision: "model-v1".into(),
                harness_revision: "harness-v1".into(),
                algorithm_revision: "algorithm-v1".into(),
                budget: 100,
                procedure_exposure_revision_id: None,
                metric_direction: MetricDirection::HigherIsBetter,
                metric_unit: "score".into(),
                positive_delta_threshold: "0.05".into(),
                negative_delta_threshold: "0.03".into(),
            }),
            work_artifact_refs: Vec::new(),
            terminal_evidence_refs: vec![terminal_receipt_id],
            created_at_us: 1,
            started_at_us: Some(1),
            ended_at_us: Some(2),
        };
        run.experiment_contract_fingerprint = run.recompute_exact_contract_fingerprint().unwrap();
        run.comparison_key = run.recompute_comparison_key().unwrap();
        run.validate().unwrap();
        let mut declaration = run.clone();
        declaration.revision_id = declaration_revision_id;
        declaration.parent_revision_id = None;
        declaration.observability = RunObservability::Declared;
        declaration.execution_status = RunExecutionStatus::Unknown;
        declaration.contract_validity = RunContractValidity::Unknown;
        declaration.terminal_evidence_refs.clear();
        declaration.ended_at_us = None;
        declaration.validate().unwrap();
        declaration.validate_successor(&run).unwrap();
        let mut run_successor = run.clone();
        run_successor.revision_id = RevisionId::new_v7();
        run_successor.parent_revision_id = Some(run.revision_id);
        run_successor
            .source_receipt_refs
            .push(SourceReceiptId::from_digest([3; 32]));
        run_successor.source_receipt_refs.sort();
        run.validate_successor(&run_successor).unwrap();
        let cas_id = CasId::from_digest([6; 32]);
        let result = ResultEvidence {
            result_evidence_id: result_id,
            revision_id: result_revision_id,
            parent_revision_id: None,
            experiment_run_id: run_id,
            experiment_run_revision_id: run_revision_id,
            result_scope: ResultScope::Complete,
            raw_artifact_refs: Vec::new(),
            raw_cas_refs: vec![cas_id],
            parsed_metric: Some(MetricValue {
                decimal: "1".into(),
                unit: "score".into(),
                uncertainty_decimal: None,
            }),
            parser_receipt: ParserReceipt {
                parser_version: "test-v1".into(),
                input_artifact_refs: Vec::new(),
                input_cas_refs: vec![cas_id],
                status: ParserStatus::Parsed,
                failure_code: None,
            },
            verifier_receipt: Some(VerifierReceipt {
                verifier_version: "test-v1".into(),
                status: VerifierStatus::Passed,
                failure_code: None,
            }),
            completeness: EvidenceCompleteness::Complete,
            failure: None,
            created_at_us: 2,
        };
        result.validate().unwrap();
        let object_row = |kind: &str,
                          row_id: String,
                          object_id: String,
                          revision_id: RevisionId,
                          payload: &JournalPayload,
                          seq| {
            let mut row = runtime_row(row_id, ObjectRowClass::Object, payload, seq).unwrap();
            row.object_kind = Some(kind.into());
            row.object_id = Some(object_id);
            row.current_revision_id = Some(revision_id.to_string());
            row
        };
        let evidence_snapshot = ProjectionSnapshot {
            frontier: 4,
            rows: vec![
                object_row(
                    "experiment_run",
                    format!("object:work:experiment_run:{}", declaration.revision_id),
                    declaration.run_id.to_string(),
                    declaration.revision_id,
                    &JournalPayload::ExperimentRunRecorded(Box::new(declaration.clone())),
                    1,
                ),
                object_row(
                    "experiment_run",
                    format!("object:work:experiment_run:{}", run.revision_id),
                    run.run_id.to_string(),
                    run.revision_id,
                    &JournalPayload::ExperimentRunRecorded(Box::new(run.clone())),
                    2,
                ),
                object_row(
                    "experiment_run",
                    format!("object:work:experiment_run:{}", run_successor.revision_id),
                    run_successor.run_id.to_string(),
                    run_successor.revision_id,
                    &JournalPayload::ExperimentRunRecorded(Box::new(run_successor.clone())),
                    3,
                ),
                object_row(
                    "result_evidence",
                    format!("object:work:result_evidence:{}", result.revision_id),
                    result.result_evidence_id.to_string(),
                    result.revision_id,
                    &JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
                    4,
                ),
            ],
        };
        let evidence_view =
            CompetingResolutionEvidenceView::for_attempts(&evidence_snapshot, [&attempt]).unwrap();
        assert_eq!(
            evidence_view.run_revisions[&result.experiment_run_revision_id],
            run
        );
        assert_eq!(
            evidence_view.current_results[&result.result_evidence_id],
            result
        );
        let alternate_id = AttemptId::new_v7();
        let open = CompetingAttemptGroup {
            competing_group_id: group_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            task_id: attempt.task_id,
            decision_boundary_ref: "decision:test".into(),
            comparison_contract_ref: None,
            origin_workstream_id: Some(workstream_id),
            origin_episode_id: None,
            member_workstream_ids: vec![workstream_id],
            member_attempt_ids: {
                let mut ids = vec![attempt_id, alternate_id];
                ids.sort();
                ids
            },
            candidate_snapshot_refs: Vec::new(),
            target_refs: vec!["target:test".into()],
            conflict_kind: CompetingConflictKind::AlternativeStrategy,
            resolution_status: CompetingResolutionStatus::Unresolved,
            selected_attempt_id: None,
            partially_integrated_attempt_ids: Vec::new(),
            resolution_evidence_refs: vec!["reason:unresolved".into()],
            source_watermark: 1,
        };
        open.validate().unwrap();
        let mut evidence_refs = vec![
            "reason:unresolved".into(),
            integration_id.to_string(),
            result_id.to_string(),
        ];
        evidence_refs.sort();
        let selected = CompetingAttemptGroup {
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: Some(open.revision_id),
            revision_generation: 2,
            resolution_status: CompetingResolutionStatus::Selected,
            selected_attempt_id: Some(attempt_id),
            resolution_evidence_refs: evidence_refs,
            source_watermark: 2,
            ..open.clone()
        };
        open.validate_successor(&selected).unwrap();
        let selected_payload = JournalPayload::CompetingAttemptGroupRecorded(Box::new(selected));
        let mut state = JournalAdmissionState::default();
        state.attempts.insert(attempt_id, (attempt.clone(), 1));
        state.competing_groups.insert(group_id, (open.clone(), 1));
        state
            .integration_events
            .insert(integration_id, (integration.clone(), 1));
        state
            .experiment_runs
            .insert(run_id, (run_successor.clone(), 2));
        state
            .experiment_run_revisions
            .insert(declaration.revision_id, (declaration, 1));
        state
            .experiment_run_revisions
            .insert(run.revision_id, (run.clone(), 2));
        state
            .experiment_run_revisions
            .insert(run_successor.revision_id, (run_successor, 3));
        state.result_evidence.insert(result_id, (result.clone(), 1));
        state
            .result_evidence_revisions
            .insert(result_revision_id, (result.clone(), 1));
        assert!(
            state
                .validate_competing_selected_command([(&selected_payload, SourceKind::Manual)])
                .is_ok()
        );

        let mut forged = match &selected_payload {
            JournalPayload::CompetingAttemptGroupRecorded(value) => value.as_ref().clone(),
            _ => unreachable!(),
        };
        forged.resolution_evidence_refs =
            vec!["reason:unresolved".into(), integration_id.to_string()];
        let forged_payload = JournalPayload::CompetingAttemptGroupRecorded(Box::new(forged));
        assert_eq!(
            state.validate_competing_selected_command([(&forged_payload, SourceKind::Manual)]),
            Err(StoreError::StoreCorrupt)
        );

        let mut empty = JournalAdmissionState::default();
        empty.competing_groups.insert(group_id, (open, 1));
        assert!(
            empty
                .validate_competing_selected_command([(&selected_payload, SourceKind::System,)])
                .is_ok()
        );
        assert_eq!(
            empty.validate_competing_selected_command([(&selected_payload, SourceKind::Manual,)]),
            Err(StoreError::StoreCorrupt)
        );
        let attempt_payload = JournalPayload::AttemptRecorded(Box::new(attempt));
        let integration_payload = JournalPayload::IntegrationEventRecorded(Box::new(integration));
        let run_payload = JournalPayload::ExperimentRunRecorded(Box::new(run));
        let result_payload = JournalPayload::ResultEvidenceRecorded(Box::new(result));
        assert_eq!(
            empty.validate_competing_selected_command([
                (&attempt_payload, SourceKind::System),
                (&integration_payload, SourceKind::System),
                (&run_payload, SourceKind::System),
                (&result_payload, SourceKind::System),
                (&selected_payload, SourceKind::Manual),
            ]),
            Err(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn unrelated_delta_does_not_reconcile_unchanged_recall_rows() {
        let payload = JournalPayload::MigrationApplied(MigrationApplied {
            migration_id: "test-recall-boundary".into(),
        });
        let mut recall = runtime_row(
            "projection:recall:test".into(),
            ObjectRowClass::Projection,
            &payload,
            1,
        )
        .unwrap();
        recall.object_kind = Some(recall_projection::RECALL_TRIGGER_INDEX_KIND.into());
        let current_checkpoint = ObjectRow::checkpoint(1, PROJECTION_GENERATION);
        let expected_checkpoint = ObjectRow::checkpoint(2, PROJECTION_GENERATION);
        let current_rows = [current_checkpoint, recall.clone()];
        let current_by_id = current_rows
            .iter()
            .map(|row| (row.row_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let expected = ProjectionSnapshot {
            frontier: 2,
            rows: vec![expected_checkpoint, recall.clone()],
        };

        assert_eq!(
            incremental_changed_rows(&expected, &current_by_id, false, false, false, false),
            vec![expected.rows[0].clone()]
        );
        assert_eq!(
            incremental_changed_rows(&expected, &current_by_id, true, false, false, false),
            expected.rows
        );
    }

    fn recall_binding(
        operation_id: OperationId,
        task_id: TaskId,
        workstream_id: WorkstreamId,
        episode_id: WorkEpisodeId,
    ) -> WorkBindingRevision {
        WorkBindingRevision {
            work_binding_revision_id: WorkBindingRevisionId::new_v7(),
            operation_id,
            revision_generation: 1,
            predecessor_revision_id: None,
            primary_binding: PrimaryWorkBinding {
                task_id: Some(task_id),
                workstream_id: Some(workstream_id),
                episode_id: Some(episode_id),
                ..PrimaryWorkBinding::default()
            },
            secondary_bindings: Vec::new(),
            scope_effect_refs: Vec::new(),
            assignment_status: AssignmentStatus::Resolved,
            evidence_refs: vec!["binding".into()],
            resolver_version: 1,
        }
    }

    #[test]
    fn recall_context_selects_newest_lane_binding_and_rejects_authority_tie() {
        let episode_id = WorkEpisodeId::new_v7();
        let task_id = TaskId::new_v7();
        let workstream_id = WorkstreamId::new_v7();
        let first_operation = OperationId::new_v7();
        let second_operation = OperationId::new_v7();
        let first = recall_binding(first_operation, task_id, workstream_id, episode_id);
        let second = recall_binding(second_operation, task_id, workstream_id, episode_id);
        assert_eq!(
            select_recall_binding(
                [(&first, 7), (&second, 9)].into_iter(),
                &[first_operation, second_operation],
                task_id,
                workstream_id,
                episode_id,
            )
            .unwrap(),
            Some(&second)
        );
        assert_eq!(
            select_recall_binding(
                [(&first, 9), (&second, 9)].into_iter(),
                &[first_operation, second_operation],
                task_id,
                workstream_id,
                episode_id,
            ),
            Err(StoreError::StoreCorrupt)
        );
    }

    fn command_id(value: &str) -> CommandId {
        CommandId::from_str(value).unwrap()
    }

    fn job_id() -> JobId {
        JobId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a4b").unwrap()
    }

    fn append(
        command: JournalCommand,
        first_seq: u64,
        rows: &mut Vec<JournalRow>,
    ) -> PreparedCommand {
        let prepared = prepare_command(&command).unwrap();
        rows.extend(rows_for_append(&prepared, first_seq, 0).unwrap());
        prepared
    }

    fn close_reconciliation() -> SourceCloseReconciliation {
        SourceCloseReconciliation::new(
            "close-proof-current",
            ExecutionLaneId::new_v7(),
            vec![SourceCloseRange {
                source_instance_id: SourceInstanceId::parse("source-current").unwrap(),
                source_revision: SourceRevision::parse("revision-current").unwrap(),
                eligible_event_manifest_refs: vec!["eligible-current".into()],
                first_sequence: 1,
                close_watermark: 1,
                observed_through_sequence: 1,
                admission_failure_observability: AdmissionFailureObservability::Complete,
                independent_reconciliation: None,
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    fn operation(revision: u32, previous: Option<u32>) -> Operation {
        Operation {
            operation_id: OperationId::new_v7(),
            host_occurrence_id: HostOccurrenceId::from_digest([0x71; 32]),
            execution_lane_id: None,
            operation_kind: OperationKind::Read,
            input_source_observation_refs: vec![SourceObservationId::from_digest([0x72; 32])],
            result_source_observation_refs: vec![],
            pairing_state: PairingState::UnmatchedIntent,
            scope_effect_ids: vec![],
            artifact_refs: vec![],
            operation_resolver_version: 1,
            operation_revision: revision,
            previous_operation_revision: previous,
        }
    }

    fn occurrence() -> HostOccurrence {
        HostOccurrence {
            host_occurrence_id: HostOccurrenceId::from_digest([0x71; 32]),
            exact_key: None,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            correlation_strength: CorrelationStrength::Unavailable,
            source_observation_refs: vec![SourceObservationId::from_digest([0x72; 32])],
            field_provenance: Vec::new(),
            normalization_state: NormalizationState::SingleSource,
            pairing_state: PairingState::UnmatchedIntent,
            possible_duplicate_group_id: None,
            correlation_resolver_version: 1,
            normalization_revision: 1,
            previous_normalization_revision: None,
        }
    }

    #[test]
    fn physical_revision_exact_repeat_keeps_first_seq_and_conflicts_fail_closed() {
        let mut state = JournalAdmissionState::default();
        let occurrence = occurrence();
        state
            .apply_payload(
                JournalPayload::HostOccurrenceNormalized(Box::new(occurrence.clone())),
                10,
            )
            .unwrap();
        state
            .apply_payload(
                JournalPayload::HostOccurrenceNormalized(Box::new(occurrence.clone())),
                20,
            )
            .unwrap();
        assert_eq!(
            state.host_occurrence_revisions[&(
                occurrence.host_occurrence_id,
                occurrence.normalization_revision
            )]
                .1,
            10
        );
        let mut conflicting_occurrence = occurrence.clone();
        conflicting_occurrence.correlation_resolver_version += 1;
        assert_eq!(
            state.apply_payload(
                JournalPayload::HostOccurrenceNormalized(Box::new(conflicting_occurrence)),
                30,
            ),
            Err(StoreError::StoreCorrupt)
        );

        let operation = operation(1, None);
        state
            .apply_payload(
                JournalPayload::OperationDerived(Box::new(operation.clone())),
                11,
            )
            .unwrap();
        state
            .apply_payload(
                JournalPayload::OperationDerived(Box::new(operation.clone())),
                21,
            )
            .unwrap();
        assert_eq!(
            state.operation_revisions[&(operation.operation_id, operation.operation_revision)].1,
            11
        );
        let mut conflicting_operation = operation;
        conflicting_operation.operation_kind = OperationKind::Search;
        assert_eq!(
            state.apply_payload(
                JournalPayload::OperationDerived(Box::new(conflicting_operation)),
                31,
            ),
            Err(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn operation_revision_restore_rejects_invalid_gap_fork_and_overflow() {
        let mut invalid = operation(1, None);
        invalid.operation_resolver_version = 0;
        let mut restored = ReducerState::default();
        restored
            .operation_revisions
            .insert((invalid.operation_id, 1), (invalid, 1));
        assert_eq!(
            restored.rebuild_revision_currents(),
            Err(StoreError::StoreCorrupt)
        );

        let first = operation(1, None);
        let mut current = BTreeMap::new();
        replace_operation(&mut current, first.clone(), 1).unwrap();
        let mut gap = first.clone();
        gap.operation_revision = 3;
        gap.previous_operation_revision = Some(2);
        assert_eq!(
            replace_operation(&mut current, gap, 2),
            Err(StoreError::StoreCorrupt)
        );

        let mut second = first.clone();
        second.operation_revision = 2;
        second.previous_operation_revision = Some(1);
        replace_operation(&mut current, second.clone(), 2).unwrap();
        let mut fork = second;
        fork.operation_kind = OperationKind::Search;
        assert_eq!(
            replace_operation(&mut current, fork, 3),
            Err(StoreError::StoreCorrupt)
        );

        let mut max = first.clone();
        max.operation_revision = u32::MAX;
        max.previous_operation_revision = Some(u32::MAX - 1);
        current.insert(max.operation_id, (max.clone(), 4));
        let mut overflow = max;
        overflow.previous_operation_revision = Some(u32::MAX);
        assert_eq!(
            replace_operation(&mut current, overflow, 5),
            Err(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn current_restore_revalidates_typed_payload_and_relation_closure() {
        let reconciliation = close_reconciliation();
        let payload = JournalPayload::SourceCloseReconciliation(reconciliation.clone());
        let row = runtime_row(
            format!(
                "runtime:reconciliation:{}",
                reconciliation.reconciliation_ref
            ),
            ObjectRowClass::Runtime,
            &payload,
            1,
        )
        .unwrap();
        let orphan_rows = vec![ObjectRow::checkpoint(1, PROJECTION_GENERATION), row.clone()];
        assert!(matches!(
            ReducerState::from_current_rows(&orphan_rows, 1),
            Err(StoreError::StoreCorrupt | StoreError::Projection)
        ));

        let mut invalid = row;
        let mut encoded: serde_json::Value =
            serde_json::from_str(invalid.payload_json.as_deref().unwrap()).unwrap();
        encoded["value"]["decision"] = serde_json::Value::String("failed".into());
        invalid.payload_json = Some(serde_json::to_string(&encoded).unwrap());
        let invalid_rows = vec![ObjectRow::checkpoint(1, PROJECTION_GENERATION), invalid];
        assert!(matches!(
            ReducerState::from_current_rows(&invalid_rows, 1),
            Err(StoreError::StoreCorrupt)
        ));
    }

    #[test]
    fn close_proof_rejects_sequence_holes_and_receipt_cohort_mismatch() {
        let source = SourceCloseRange {
            source_instance_id: SourceInstanceId::parse("source-hole").unwrap(),
            source_revision: SourceRevision::parse("revision-hole").unwrap(),
            eligible_event_manifest_refs: vec!["eligible-hole".into()],
            first_sequence: 1,
            close_watermark: 3,
            observed_through_sequence: 3,
            admission_failure_observability: AdmissionFailureObservability::Complete,
            independent_reconciliation: None,
        };
        let known = KnownSourceRange {
            sequences: [1, 3].into_iter().collect(),
            sequence_origin: None,
            close_watermark: Some(3),
            eligible_event_manifest_refs: ["eligible-hole".into()].into_iter().collect(),
        };
        assert_eq!(
            validate_reconciliation_source(&source, &known),
            Err(StoreError::StoreCorrupt)
        );

        let proof = SourceCloseReconciliation::new(
            "close-proof-hole",
            ExecutionLaneId::new_v7(),
            vec![source],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(proof_matches_complete_refs(
            &proof,
            &["source-hole@revision-hole".into()],
            &["source-hole@revision-hole:3".into()],
            &["eligible-hole".into()],
        ));
        assert!(!proof_matches_complete_refs(
            &proof,
            &["source-other@revision-other".into()],
            &["source-other@revision-other:3".into()],
            &["eligible-other".into()],
        ));

        let head_gap_known = KnownSourceRange {
            sequences: [2, 3].into_iter().collect(),
            sequence_origin: Some(1),
            close_watermark: Some(3),
            eligible_event_manifest_refs: ["eligible-hole".into()].into_iter().collect(),
        };
        let mut head_gap = proof.sources[0].clone();
        head_gap.observed_through_sequence = 0;
        assert_eq!(
            validate_reconciliation_source(&head_gap, &head_gap_known),
            Ok(())
        );
        head_gap.observed_through_sequence = 3;
        assert_eq!(
            validate_reconciliation_source(&head_gap, &head_gap_known),
            Err(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn empty_reconciliation_frontier_is_bounded_and_validates_limit() {
        let snapshot = ProjectionSnapshot {
            frontier: 7,
            rows: vec![ObjectRow::checkpoint(7, PROJECTION_GENERATION)],
        };
        assert_eq!(
            snapshot.reconciliation_frontier(2).unwrap(),
            ReconciliationFrontier {
                frontier: 7,
                items: Vec::new(),
            }
        );
        assert_eq!(
            snapshot.reconciliation_frontier(0),
            Err(StoreError::InvalidInput)
        );
    }

    #[test]
    fn missing_incarnation_is_isolated_by_observation_not_child_or_spawn() {
        let observation_id = SourceObservationId::from_digest([7; 32]);
        let mut lifecycle = LaneLifecycleEvidence {
            host_session_id: "session-a".into(),
            agent_id: "agent-a".into(),
            incarnation_ref: None,
            child_session_id: Some("child-a".into()),
            host_lane_key: "lane-a".into(),
            parent_host_lane_key: None,
            spawn_event_ref: Some("spawn-a".into()),
            terminal_event_ref: None,
            terminal_kind: None,
            host_final_return: false,
            source_close_ref: None,
            parent_session_end_ref: None,
            liveness_probe_ref: None,
            liveness_state: LivenessState::Live,
            lane_sequence: 1,
            adapter_manifest_ref: "manifest-a".into(),
            eligible_event_manifest_ref: "eligible-a".into(),
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            reasoning_visibility: Vec::new(),
        };
        assert_eq!(
            lifecycle_incarnation_ref(&lifecycle, observation_id),
            format!("source-observation:{observation_id}")
        );
        lifecycle.incarnation_ref = Some("explicit-a".into());
        assert_eq!(
            lifecycle_incarnation_ref(&lifecycle, observation_id),
            "explicit-a"
        );
    }

    #[test]
    fn unowned_quarantine_still_returns_existing_gap_for_lost_ack() {
        let gap = CaptureGapMarkerEvidence {
            marker_id: "quarantine-a".into(),
            reconciliation_revision: 1,
            predecessor_revision: None,
            source_ref: "unresolved-quarantine".into(),
            session_ref: "unresolved-quarantine".into(),
            turn_ref: None,
            tool_ref: None,
            failure_reason: "corrupt_segment".into(),
            redacted_fingerprint: "a".repeat(64),
            attempted_bytes: 0,
            last_durable_watermark: 0,
            provenance: ReconciliationProvenance::QuarantineRecovery,
            import_ref: "quarantine-import-a".into(),
            reconciled: false,
            reconciliation_refs: Vec::new(),
        };
        let row = physical_object_row(
            ObjectFamily::Evidence,
            "capture_gap_marker",
            gap.marker_id.clone(),
            format!("{}@1", gap.marker_id),
            &JournalPayload::CaptureGapMarkerRecorded(Box::new(gap)),
            5,
        )
        .unwrap();
        let snapshot = ProjectionSnapshot {
            frontier: 5,
            rows: vec![ObjectRow::checkpoint(5, PROJECTION_GENERATION), row],
        };
        let descriptor = ReconciliationArtifactDescriptor {
            kind: ReconciliationArtifactKind::Quarantine,
            artifact_id: "quarantine-a".into(),
            marker_id: None,
            redacted_fingerprint: Some("a".repeat(64)),
            session_ref: None,
            source_ref: None,
        };
        let result = snapshot
            .reconciliation_artifact_context(std::slice::from_ref(&descriptor), 1)
            .unwrap();
        assert_eq!(result.contexts.len(), 1);
        assert_eq!(result.contexts[0].descriptor, descriptor);
        assert_eq!(
            result.contexts[0].ownership,
            ReconciliationArtifactOwnership::Unowned
        );
        assert_eq!(result.contexts[0].dependencies.len(), 1);
        assert!(matches!(
            result.contexts[0].dependencies[0].payload,
            JournalPayload::CaptureGapMarkerRecorded(_)
        ));

        let generic = ReconciliationArtifactDescriptor {
            kind: ReconciliationArtifactKind::GapMarker,
            artifact_id: "artifact-a".into(),
            marker_id: Some("quarantine-a".into()),
            redacted_fingerprint: Some("a".repeat(64)),
            session_ref: Some("unresolved-quarantine".into()),
            source_ref: Some("unresolved-quarantine".into()),
        };
        let generic_result = snapshot
            .reconciliation_artifact_context(std::slice::from_ref(&generic), 1)
            .unwrap();
        assert_eq!(
            generic_result.contexts[0].ownership,
            ReconciliationArtifactOwnership::Unowned
        );
        assert_eq!(generic_result.contexts[0].dependencies.len(), 1);
    }

    #[test]
    fn outage_descriptor_returns_exact_current_outage_context() {
        let outage_id = CaptureOutageIntervalId::new_v7();
        let outage = CaptureOutageInterval {
            capture_outage_interval_id: outage_id,
            reconciliation_revision: 1,
            predecessor_revision: None,
            source_ref: "source-a@revision-a".into(),
            session_ref: "session-a".into(),
            first_missing_sequence: 2,
            last_missing_sequence: 2,
            positive_source: CaptureOutagePositiveSource::MonotonicSequenceGap,
            positive_evidence_refs: vec!["sequence-gap-a".into()],
            reconciled: false,
            reconciliation_refs: Vec::new(),
        };
        let row = physical_object_row(
            ObjectFamily::Evidence,
            "capture_outage_interval",
            outage_id.to_string(),
            format!("{outage_id}@1"),
            &JournalPayload::CaptureOutageIntervalRecorded(Box::new(outage)),
            8,
        )
        .unwrap();
        let snapshot = ProjectionSnapshot {
            frontier: 8,
            rows: vec![ObjectRow::checkpoint(8, PROJECTION_GENERATION), row],
        };
        let descriptor = ReconciliationArtifactDescriptor {
            kind: ReconciliationArtifactKind::Outage,
            artifact_id: outage_id.to_string(),
            marker_id: None,
            redacted_fingerprint: None,
            session_ref: None,
            source_ref: None,
        };
        let result = snapshot
            .reconciliation_artifact_context(&[descriptor], 1)
            .unwrap();
        assert_eq!(
            result.contexts[0].ownership,
            ReconciliationArtifactOwnership::Unowned
        );
        assert_eq!(result.contexts[0].dependencies.len(), 1);
        assert!(matches!(
            result.contexts[0].dependencies[0].payload,
            JournalPayload::CaptureOutageIntervalRecorded(_)
        ));
    }

    #[tokio::test]
    async fn artifact_dependency_closure_fails_closed_at_safety_ceiling() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let outage_event = |id: CaptureOutageIntervalId, sequence: u64| {
            JournalEventDraft::runtime(
                i64::try_from(sequence).unwrap(),
                [0; 32],
                "capture-v1",
                JournalPayload::CaptureOutageIntervalRecorded(Box::new(CaptureOutageInterval {
                    capture_outage_interval_id: id,
                    reconciliation_revision: 1,
                    predecessor_revision: None,
                    source_ref: "source-bounded@revision-a".into(),
                    session_ref: "session-bounded".into(),
                    first_missing_sequence: sequence,
                    last_missing_sequence: sequence,
                    positive_source: CaptureOutagePositiveSource::MonotonicSequenceGap,
                    positive_evidence_refs: vec![format!("sequence-gap-{sequence}")],
                    reconciled: false,
                    reconciliation_refs: Vec::new(),
                })),
            )
        };

        let outage_ids = (1..=MAX_S10_RECONCILIATION_DEPENDENCIES)
            .map(|_| CaptureOutageIntervalId::new_v7())
            .collect::<Vec<_>>();
        let events = outage_ids
            .iter()
            .copied()
            .enumerate()
            .map(|(index, id)| outage_event(id, u64::try_from(index + 1).unwrap()))
            .collect();
        writer
            .commit(
                &JournalCommand::new(command_id("01890f47-6a4a-7cc1-98b9-01890f476a60"), events)
                    .unwrap(),
                1,
            )
            .await
            .unwrap();
        let descriptor = ReconciliationArtifactDescriptor {
            kind: ReconciliationArtifactKind::Outage,
            artifact_id: outage_ids[0].to_string(),
            marker_id: None,
            redacted_fingerprint: None,
            session_ref: None,
            source_ref: None,
        };
        let within_ceiling = writer
            .reconciliation_artifact_context(std::slice::from_ref(&descriptor), 1)
            .await
            .unwrap();
        assert_eq!(within_ceiling.contexts.len(), 1);
        assert_eq!(
            within_ceiling.contexts[0].dependencies.len(),
            MAX_S10_RECONCILIATION_DEPENDENCIES
        );
        assert!(
            within_ceiling.contexts[0]
                .dependencies
                .windows(2)
                .all(|pair| pair[0].row_id < pair[1].row_id)
        );

        let overflow_id = CaptureOutageIntervalId::new_v7();
        writer
            .commit(
                &JournalCommand::new(
                    command_id("01890f47-6a4a-7cc1-98b9-01890f476a61"),
                    vec![outage_event(
                        overflow_id,
                        u64::try_from(MAX_S10_RECONCILIATION_DEPENDENCIES + 1).unwrap(),
                    )],
                )
                .unwrap(),
                2,
            )
            .await
            .unwrap();
        let projected_before = writer.project().await.unwrap();
        let journal_before = writer.journal_rows().await.unwrap();
        assert_eq!(
            writer
                .reconciliation_artifact_context(std::slice::from_ref(&descriptor), 1)
                .await,
            Err(StoreError::ReconciliationDependencyOverflow)
        );
        assert_eq!(writer.journal_rows().await.unwrap(), journal_before);
        assert_eq!(writer.project().await.unwrap(), projected_before);
    }

    #[test]
    fn reducer_coalesces_dirty_outbox_and_recovers_lease_with_seq_gaps() {
        let dirty = DirtyTarget {
            target_kind: DirtyTargetKind::ObjectsProjection,
            target_id: "objects".into(),
            algorithm_revision: "v1".into(),
            source_watermark: 9,
        };
        let job = DurableJob {
            job_id: job_id(),
            idempotency_key: "job-key".into(),
            target_revision: "revision-1".into(),
            target_watermark: 9,
            target_generation: 1,
            kind: "projection_rebuild".into(),
            algorithm_revision: "v1".into(),
            model_id: None,
            priority: 1,
            state: JobStatus::Queued,
            attempt: 1,
            backoff_until_us: None,
            config_hash: [7; 32],
            budget: JobBudget {
                max_items: 1,
                max_bytes: None,
                max_input_tokens: None,
                max_output_tokens: None,
                max_calls: None,
                max_wall_time_ms: 250,
            },
            terminal: None,
            lease_until_us: None,
        };
        let mut forged_initial_lease = job.clone();
        forged_initial_lease.state = JobStatus::Leased;
        forged_initial_lease.lease_until_us = Some(100);
        let mut forged_rows = Vec::new();
        append(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    0,
                    [0; 32],
                    "v1",
                    JournalPayload::JobState(forged_initial_lease),
                )],
            )
            .unwrap(),
            1,
            &mut forged_rows,
        );
        assert_eq!(reduce_journal(&forged_rows), Err(StoreError::StoreCorrupt));
        let mut forged_terminal = job.clone();
        forged_terminal.state = JobStatus::Succeeded;
        forged_terminal.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Succeeded,
            reason: JobTerminalReason::Completed,
            result_ref: Some("revision-1".into()),
        }));
        let mut forged_rows = Vec::new();
        append(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    0,
                    [0; 32],
                    "v1",
                    JournalPayload::JobState(job.clone()),
                )],
            )
            .unwrap(),
            1,
            &mut forged_rows,
        );
        append(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    1,
                    [0; 32],
                    "v1",
                    JournalPayload::JobState(forged_terminal),
                )],
            )
            .unwrap(),
            2,
            &mut forged_rows,
        );
        assert_eq!(reduce_journal(&forged_rows), Err(StoreError::StoreCorrupt));
        let mut rows = Vec::new();
        append(
            JournalCommand::new(
                command_id("01890f47-6a4a-7cc1-98b9-01890f476a4a"),
                vec![
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::MigrationApplied(MigrationApplied {
                            migration_id: "L0001".into(),
                        }),
                    ),
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::DirtyTarget(dirty.clone()),
                    ),
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::OutboxEnqueued(OutboxEntry {
                            outbox_id: "outbox-1".into(),
                            dirty: dirty.clone(),
                        }),
                    ),
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::JobState(job.clone()),
                    ),
                ],
            )
            .unwrap(),
            1,
            &mut rows,
        );
        let first_len = rows.len();
        append(
            JournalCommand::new(
                command_id("01890f47-6a4a-7cc1-98b9-01890f476a4c"),
                vec![
                    JournalEventDraft::runtime(
                        1,
                        [0; 32],
                        "v1",
                        JournalPayload::DirtyTarget(dirty.clone()),
                    ),
                    JournalEventDraft::runtime(
                        1,
                        [0; 32],
                        "v1",
                        JournalPayload::OutboxEnqueued(OutboxEntry {
                            outbox_id: "outbox-1".into(),
                            dirty,
                        }),
                    ),
                    JournalEventDraft::runtime(
                        1,
                        [0; 32],
                        "v1",
                        JournalPayload::JobLease(JobLease {
                            job_id: job.job_id,
                            target_generation: 1,
                            attempt: 2,
                            lease_until_us: 100,
                        }),
                    ),
                ],
            )
            .unwrap(),
            10,
            &mut rows,
        );
        let snapshot = reduce_journal(&rows).unwrap();
        let first = reduce_journal(&rows[..first_len]).unwrap();
        let mut restored = ReducerState::from_current_rows(&first.rows, first.frontier).unwrap();
        let delta = &rows[first_len..];
        validate_delta(first.frontier, snapshot.frontier, delta).unwrap();
        for batch in ordered_command_batches(delta).unwrap() {
            for row in &batch {
                apply_event(&mut restored, row, &batch).unwrap();
            }
        }
        assert_eq!(restored.into_snapshot(snapshot.frontier).unwrap(), snapshot);
        assert_eq!(snapshot.frontier, 12);
        assert_eq!(
            snapshot
                .data_rows()
                .filter(|row| row.row_id.starts_with("runtime:dirty:"))
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .data_rows()
                .filter(|row| row.row_id.starts_with("runtime:outbox:"))
                .count(),
            1
        );
        let job_row = snapshot
            .row(&format!("runtime:job:{}", job.job_id))
            .unwrap();
        let projected: JournalPayload =
            serde_json::from_str(job_row.payload_json.as_deref().unwrap()).unwrap();
        let JournalPayload::JobState(projected) = projected else {
            panic!("expected job state")
        };
        assert_eq!(projected.state, JobStatus::Leased);
        assert_eq!(projected.attempt, 2);
        assert_eq!(projected.lease_until_us, Some(100));
    }

    #[tokio::test]
    async fn projection_commit_fault_does_not_advance_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let command = JournalCommand::new(
            command_id("01890f47-6a4a-7cc1-98b9-01890f476a4d"),
            vec![JournalEventDraft::runtime(
                1,
                [0; 32],
                "v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "fault".into(),
                    algorithm_revision: "v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let before = read_object_rows(&objects).await.unwrap();
        let worker = ProjectionWorker::new(journal, objects.clone());
        assert_eq!(
            worker.catch_up_with_commit_fault().await,
            Err(StoreError::Projection)
        );
        assert_eq!(read_object_rows(&objects).await.unwrap(), before);
        assert_eq!(
            worker.catch_up().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
    }

    #[tokio::test]
    async fn checkpoint_ahead_of_journal_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let writer = JournalWriter::open(&root).await.unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let worker = ProjectionWorker::new(journal, objects);
        worker
            .commit_rows(
                &[ObjectRow::checkpoint(10_000, PROJECTION_GENERATION)],
                false,
                false,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!(worker.catch_up().await, Err(StoreError::StoreCorrupt));
        drop(writer);
    }

    #[tokio::test]
    async fn no_delta_is_version_stable_and_corrupt_current_row_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let writer = JournalWriter::open(&root).await.unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let worker = ProjectionWorker::new(journal, objects.clone());
        let before_version = objects.version().await.unwrap();
        worker.catch_up().await.unwrap();
        assert_eq!(objects.version().await.unwrap(), before_version);

        let mut migration = read_object_rows(&objects)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.row_id == "projection:migration:L0001")
            .unwrap();
        migration.payload_json = Some(
            JournalPayload::ConfigAudit(crate::ConfigAudit {
                config_version: 1,
                effective_config_hash: [0; 32],
            })
            .canonical_json()
            .unwrap(),
        );
        worker
            .commit_rows(&[migration], false, false, false, false)
            .await
            .unwrap();
        assert!(matches!(
            worker.catch_up().await,
            Err(StoreError::StoreCorrupt | StoreError::Projection)
        ));
        drop(writer);
    }

    #[tokio::test]
    async fn checkpoint_inside_command_makes_delta_partial_and_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let dirty = DirtyTarget {
            target_kind: DirtyTargetKind::ObjectsProjection,
            target_id: "partial".into(),
            algorithm_revision: "v1".into(),
            source_watermark: 1,
        };
        writer
            .commit(
                &JournalCommand::new(
                    command_id("01890f47-6a4a-7cc1-98b9-01890f476a4e"),
                    vec![
                        JournalEventDraft::runtime(
                            1,
                            [0; 32],
                            "v1",
                            JournalPayload::DirtyTarget(dirty.clone()),
                        ),
                        JournalEventDraft::runtime(
                            1,
                            [0; 32],
                            "v1",
                            JournalPayload::OutboxEnqueued(OutboxEntry {
                                outbox_id: "partial".into(),
                                dirty,
                            }),
                        ),
                    ],
                )
                .unwrap(),
                1,
            )
            .await
            .unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let worker = ProjectionWorker::new(journal, objects);
        worker
            .commit_rows(
                &[ObjectRow::checkpoint(3, PROJECTION_GENERATION)],
                false,
                false,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!(worker.catch_up().await, Err(StoreError::StoreCorrupt));
    }
}
