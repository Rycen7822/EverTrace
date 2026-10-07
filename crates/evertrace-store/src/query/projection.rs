//! L0002 projection workers over one validated L0001 object frontier.

use std::collections::{BTreeMap, BTreeSet};

use arrow_array::RecordBatchIterator;
use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{EvidenceSurface, HostOccurrence, Operation, ScopeEffect, SourceReceipt},
    ids::{
        AttemptId, CompetingAttemptGroupId, ExecutionLaneId, ExperimentRunId, HostOccurrenceId,
        IntegrationEventId, OperationBurstId, OperationId, ProcedureNegativeEvidenceId,
        ProcedureUsageId, RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId,
        RepositoryId, ResultEvidenceId, ScopeEffectId, SourceObservationId, SourceReceiptId,
        TaskId, WorkArtifactId, WorkBindingRevisionId, WorkEpisodeId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId, WorktreeTransitionId,
    },
    procedure::{
        ProcedureNegativeEvidence, ProcedureNegativeReviewEvent, ProcedureRevision,
        ProcedureUsageRevision,
    },
    repository::{
        IntegrationEvent, RecoveryApplication, RecoveryBundle, RecoveryCaptureRequest,
        RepositoryInstance, WorktreeInstance, WorktreeSnapshot, WorktreeTransition,
    },
    revision::RevisionId,
    semantic::{
        Atom, CoreMembership, GlobalSuccessorSupportContract, ResultEvidence, RevisionProposal,
        SemanticDigest, WikiProjection,
    },
    work::{
        Attempt, CaptureReceipt, CompetingAttemptGroup, ExecutionLane, ExperimentRun,
        OperationBurst, SegmentationCorrection, Task, WorkArtifact, WorkBindingRevision,
        WorkCheckpoint, WorkEpisode, Workstream,
    },
};
use lancedb::Table;

use crate::{
    JournalPayload, ObjectRow, ObjectRowKind, ProjectionSnapshot, StoreError,
    projections::{
        ProjectionJournalDelta, l3_core_projection, procedure_context_effect, recall_need,
        recall_trigger_contract, synthesis::wiki_render_identity, validate_delta, wiki_projection,
    },
    relations::{
        RelationProjectionRow, build_attempt_relation_rows, build_autoresearch_relation_rows,
        build_capture_relation_rows, build_core_support_relation_rows, build_episode_relation_rows,
        build_operation_burst_relation_rows, build_physical_relation_rows,
        build_procedure_relation_rows, build_procedure_usage_relation_rows,
        build_recovery_application_relation_rows, build_recovery_relation_rows,
        build_repository_relation_rows, build_segmentation_correction_relation_rows,
        build_semantic_digest_relation_rows, build_semantic_relation_rows,
        build_wiki_relation_rows, build_work_binding_relation_rows,
        build_work_identity_relation_rows,
    },
    search::{SearchProjectionRow, read_search_rows, search_batch},
    sqlite_state::SqliteHandle,
};

use super::derive::{exact_identifier_row, surface_row, wiki_search_row};
use super::relation_assembly::{
    add_attempt, add_autoresearch, add_burst, add_capture, add_correction, add_episode,
    add_physical, add_recovery, add_repository, add_semantic, add_work_binding, add_work_identity,
    index_typed_ids, update_capture_relations,
};

/// The validated persisted L0002 base for one journal frontier.
struct L0002Handoff {
    frontier: u64,
    relation_rows: Vec<RelationProjectionRow>,
    search: Vec<SearchProjectionRow>,
    relation_frontier: u64,
    search_frontier: u64,
    versions: [u64; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L0002ProjectionSnapshot {
    pub frontier: u64,
    pub relations: Vec<RelationProjectionRow>,
    pub search: Vec<SearchProjectionRow>,
}

pub fn object_projection_hash(objects: &ProjectionSnapshot) -> Result<[u8; 32], StoreError> {
    canonical_hash(
        "evertrace_objects_projection",
        CanonicalValue::Sequence(
            objects
                .rows
                .iter()
                .map(|row| {
                    CanonicalValue::Sequence(vec![
                        CanonicalValue::String(row.row_id.clone()),
                        CanonicalValue::String(row.row_kind.as_str().into()),
                        option(row.row_class.map(|value| value.as_str().into())),
                        option(row.object_family.map(|value| value.as_str().into())),
                        option(row.object_kind.clone()),
                        option(row.object_id.clone()),
                        option(row.current_revision_id.clone()),
                        option(row.lifecycle.clone()),
                        option(row.epistemic.clone()),
                        option(row.authority.clone()),
                        option(row.publication_state.clone()),
                        option(row.support_state.clone()),
                        option(row.project_id.clone()),
                        option(row.repository_id.clone()),
                        option(row.worktree_id.clone()),
                        option(row.task_id.clone()),
                        option(row.workstream_id.clone()),
                        option(row.session_id.clone()),
                        option(row.payload_json.clone()),
                        CanonicalValue::Integer(i128::from(row.source_event_seq)),
                        CanonicalValue::Integer(i128::from(row.projection_generation)),
                    ])
                })
                .collect(),
        ),
    )
}

impl L0002ProjectionSnapshot {
    pub fn relation_hash(&self) -> Result<[u8; 32], StoreError> {
        canonical_hash(
            "evertrace_relations_projection",
            relation_values(&self.relations),
        )
    }

    pub fn search_hash(&self) -> Result<[u8; 32], StoreError> {
        canonical_hash("evertrace_search_projection", search_values(&self.search))
    }
}

#[derive(Clone)]
pub struct L0002ProjectionWorker {
    sqlite: SqliteHandle,
    search: Table,
}

impl L0002ProjectionWorker {
    pub(crate) fn new(sqlite: SqliteHandle, search: Table) -> Self {
        Self { sqlite, search }
    }

    pub(crate) async fn rebuild_for_restore(
        &self,
        objects: &ProjectionSnapshot,
    ) -> Result<(), StoreError> {
        let expected = derive_l0002_projections(objects)?;
        let relations = self
            .sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .relation_rows()?;
        let search = read_search_rows(&self.search).await?;
        commit_relation_rows(&self.sqlite, &relations, &expected.relations)?;
        commit_search_rows(&self.search, &search, &expected.search, false).await?;
        if self
            .sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .relation_rows()?
            != expected.relations
            || read_search_rows(&self.search).await? != expected.search
        {
            return Err(StoreError::Projection);
        }
        Ok(())
    }

    pub async fn catch_up(
        &self,
        objects: &ProjectionSnapshot,
    ) -> Result<L0002ProjectionSnapshot, StoreError> {
        Ok(self.catch_up_inner(objects, None, false, false).await?.0)
    }

    /// The ordinary complete path with its actual-derive flag. Only a run that
    /// really derived and read every persisted row back establishes the
    /// private full-content grade; the checkpoint early return does not.
    pub(crate) async fn catch_up_validated_proof(
        &self,
        objects: &ProjectionSnapshot,
        journal_delta: Option<ProjectionJournalDelta>,
    ) -> Result<(L0002ProjectionSnapshot, [u64; 2], bool), StoreError> {
        self.catch_up_inner(objects, journal_delta, false, false)
            .await
    }

    /// Complete one confirmed closed capture successor from an already proven
    /// complete L0002 frontier without rebuilding the all-object typed maps.
    /// Both derived families must still sit on the proven base frontier; a
    /// checkpoint already at this frontier is a legal no-op. Any other base
    /// fails closed instead of deriving from an unproven predecessor.
    pub(crate) async fn catch_up_capture_delta(
        &self,
        frontier: u64,
        base_frontier: u64,
        changed_rows: &[ObjectRow],
        journal_delta: ProjectionJournalDelta,
    ) -> Result<[u64; 2], StoreError> {
        self.catch_up_capture_delta_inner(
            frontier,
            base_frontier,
            changed_rows,
            journal_delta,
            false,
            false,
        )
        .await
    }

    async fn catch_up_capture_delta_inner(
        &self,
        frontier: u64,
        base_frontier: u64,
        changed_rows: &[ObjectRow],
        journal_delta: ProjectionJournalDelta,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<[u64; 2], StoreError> {
        let handoff = self.prepare_handoff(frontier, Some(journal_delta)).await?;
        if handoff.relation_frontier == handoff.frontier
            && handoff.search_frontier == handoff.frontier
        {
            return Ok(handoff.versions);
        }
        if handoff.relation_frontier != base_frontier || handoff.search_frontier != base_frontier {
            return Err(StoreError::StoreCorrupt);
        }
        let relations = update_capture_relations(&handoff.relation_rows, changed_rows, frontier)?;
        let search = capture_delta_search(&handoff.search, changed_rows, frontier)?;
        self.commit_expected(
            handoff,
            L0002ProjectionSnapshot {
                frontier,
                relations,
                search,
            },
            fail_relation_commit,
            fail_search_commit,
        )
        .await
        .map(|(_, versions)| versions)
    }

    async fn catch_up_inner(
        &self,
        objects: &ProjectionSnapshot,
        journal_delta: Option<ProjectionJournalDelta>,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<(L0002ProjectionSnapshot, [u64; 2], bool), StoreError> {
        let handoff = self
            .prepare_handoff(objects.frontier, journal_delta)
            .await?;
        if handoff.relation_frontier == handoff.frontier
            && handoff.search_frontier == handoff.frontier
        {
            return Ok((
                L0002ProjectionSnapshot {
                    frontier: handoff.frontier,
                    relations: handoff.relation_rows,
                    search: handoff.search,
                },
                handoff.versions,
                false,
            ));
        }
        let expected = derive_l0002_projections(objects)?;
        let (snapshot, versions) = self
            .commit_expected(handoff, expected, fail_relation_commit, fail_search_commit)
            .await?;
        Ok((snapshot, versions, true))
    }

    /// The fused ordinary path: the objects producer already fed the
    /// accumulator row-by-row and staged its first derive-classed error.
    /// The original operation order is preserved exactly: the persisted
    /// handoff validates first (a native handoff error wins over any staged
    /// derive error); a checkpoint-complete handoff is a legal NoOp that never
    /// exposes a staged derive error; only a handoff that really needs
    /// derivation finishes the accumulator and commits the families.
    pub(crate) async fn catch_up_fused_handoff(
        &self,
        objects_frontier: u64,
        journal_delta: Option<ProjectionJournalDelta>,
        accumulator: Box<L0002RowAccumulator>,
    ) -> Result<([u64; 2], bool), StoreError> {
        let handoff = self
            .prepare_handoff(objects_frontier, journal_delta)
            .await?;
        if handoff.relation_frontier == handoff.frontier
            && handoff.search_frontier == handoff.frontier
        {
            // The legal NoOp never runs the derivation and never exposes a
            // staged derive error; the accumulator and its staging drop with it.
            return Ok((handoff.versions, false));
        }
        let expected = accumulator.finish(handoff.frontier)?;
        let (_, versions) = self
            .commit_expected(handoff, expected, false, false)
            .await?;
        Ok((versions, true))
    }

    /// Read and validate the complete persisted L0002 base for one journal
    /// frontier: every old relation/search row, the actual family epochs and
    /// search version, and the complete journal delta from each checkpoint.
    async fn prepare_handoff(
        &self,
        objects_frontier: u64,
        journal_delta: Option<ProjectionJournalDelta>,
    ) -> Result<L0002Handoff, StoreError> {
        let (journal_epoch, committed_frontier, relations_epoch, relation_frontier) = {
            let mut state = self.sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
            let stamp = state.stamp()?;
            let relations = state.relation_rows()?;
            let relation_frontier = checkpoint_relation(&relations)?;
            (
                stamp.journal_epoch,
                stamp.frontier,
                stamp.relations_epoch,
                relation_frontier,
            )
        };
        self.search
            .checkout_latest()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let search_version = self
            .search
            .version()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let search = read_search_rows(&self.search).await?;
        if self
            .search
            .version()
            .await
            .map_err(|_| StoreError::LanceDb)?
            != search_version
        {
            return Err(StoreError::StoreCorrupt);
        }
        let search_frontier = checkpoint_search(&search)?;
        let current_versions = [relations_epoch, search_version];
        let journal_delta = journal_delta.and_then(|delta| delta.at_epoch(journal_epoch));
        let journal_frontier = if let Some(frontier) = journal_delta
            .as_ref()
            .and_then(ProjectionJournalDelta::frontier)
        {
            // The preceding objects catch-up validated the actual delta's end
            // against this exact journal epoch, not a reserved seq.
            frontier
        } else {
            committed_frontier
        };
        if objects_frontier != journal_frontier
            || relation_frontier > journal_frontier
            || search_frontier > journal_frontier
        {
            return Err(StoreError::StoreCorrupt);
        }
        let relation_rows = self
            .sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .relation_rows()?;
        if checkpoint_relation(&relation_rows)? != relation_frontier {
            return Err(StoreError::StoreCorrupt);
        }
        for checkpoint in BTreeSet::from([relation_frontier, search_frontier]) {
            let persisted_delta;
            let delta = if let Some(rows) = journal_delta
                .as_ref()
                .and_then(|delta| delta.rows_after(checkpoint))
            {
                rows
            } else {
                persisted_delta = self
                    .sqlite
                    .lock()
                    .map_err(|_| StoreError::StoreCorrupt)?
                    .rows_after(checkpoint)?;
                persisted_delta.as_slice()
            };
            // Each distinct checkpoint still validates the complete command
            // delta against the frontier of the current physical journal.
            validate_delta(checkpoint, journal_frontier, delta)?;
        }
        // No downstream derivation needs journal payloads. Release the handoff
        // before constructing the relation/search state, including large deltas.
        drop(journal_delta);
        Ok(L0002Handoff {
            frontier: journal_frontier,
            relation_rows,
            search,
            relation_frontier,
            search_frontier,
            versions: current_versions,
        })
    }

    /// Commit the expected derived families, read every persisted row back and
    /// only then return their real epochs and search version.
    async fn commit_expected(
        &self,
        handoff: L0002Handoff,
        expected: L0002ProjectionSnapshot,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<(L0002ProjectionSnapshot, [u64; 2]), StoreError> {
        if fail_relation_commit {
            return Err(StoreError::Projection);
        }
        commit_relation_rows(&self.sqlite, &handoff.relation_rows, &expected.relations)?;
        commit_search_rows(
            &self.search,
            &handoff.search,
            &expected.search,
            fail_search_commit,
        )
        .await?;
        let (relations_epoch_after, relations) = {
            let state = self.sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
            (state.relations_epoch(), state.relation_rows()?)
        };
        let search_after = read_search_rows(&self.search).await?;
        let search_version_after = self
            .search
            .version()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let persisted = L0002ProjectionSnapshot {
            frontier: expected.frontier,
            relations,
            search: search_after,
        };
        if persisted != expected {
            return Err(StoreError::Projection);
        }
        Ok((persisted, [relations_epoch_after, search_version_after]))
    }

    #[cfg(test)]
    async fn catch_up_with_fault(
        &self,
        objects: &ProjectionSnapshot,
        journal_delta: Option<ProjectionJournalDelta>,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<L0002ProjectionSnapshot, StoreError> {
        Ok(self
            .catch_up_inner(
                objects,
                journal_delta,
                fail_relation_commit,
                fail_search_commit,
            )
            .await?
            .0)
    }

    #[cfg(test)]
    pub(crate) async fn catch_up_capture_delta_with_fault(
        &self,
        frontier: u64,
        base_frontier: u64,
        changed_rows: &[ObjectRow],
        journal_delta: ProjectionJournalDelta,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<[u64; 2], StoreError> {
        self.catch_up_capture_delta_inner(
            frontier,
            base_frontier,
            changed_rows,
            journal_delta,
            fail_relation_commit,
            fail_search_commit,
        )
        .await
    }

    pub async fn current(&self) -> Result<L0002ProjectionSnapshot, StoreError> {
        let relations = self
            .sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .relation_rows()?;
        let search = read_search_rows(&self.search).await?;
        let relation_frontier = checkpoint_relation(&relations)?;
        let search_frontier = checkpoint_search(&search)?;
        if relation_frontier != search_frontier {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(L0002ProjectionSnapshot {
            frontier: relation_frontier,
            relations,
            search,
        })
    }
}

/// The search-side delta of one closed capture: only a new evidence surface
/// (with the receipt that actually authorizes its observation) plus the moved
/// checkpoint. No closed capture payload is allowlisted for exact-identifier
/// text, and its new identifiers cannot alter any existing row's currentness.
fn capture_delta_search(
    current: &[SearchProjectionRow],
    changed_rows: &[ObjectRow],
    frontier: u64,
) -> Result<Vec<SearchProjectionRow>, StoreError> {
    let mut rows = current.iter().cloned().collect::<BTreeSet<_>>();
    let checkpoint = rows
        .iter()
        .find(|row| row.row_id == crate::search::SEARCH_CHECKPOINT_ID)
        .cloned()
        .ok_or(StoreError::StoreCorrupt)?;
    if !rows.remove(&checkpoint) {
        return Err(StoreError::StoreCorrupt);
    }
    let mut receipts = Vec::new();
    let mut surfaces = Vec::new();
    for row in changed_rows {
        let payload_json = row
            .payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?;
        let payload: JournalPayload =
            serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
        match payload {
            JournalPayload::SourceReceiptRecorded(value) => {
                receipts.push((*value, row.source_event_seq));
            }
            JournalPayload::EvidenceSurfaceRecorded(value) => {
                surfaces.push((*value, row.source_event_seq));
            }
            _ => {}
        }
    }
    for (surface, seq) in surfaces {
        surface.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let mut matching = receipts.iter().filter(|(receipt, _)| {
            receipt.source_observation_id == surface.source_observation_revision_ref
        });
        let receipt = &matching.next().ok_or(StoreError::StoreCorrupt)?.0;
        if matching.next().is_some() {
            return Err(StoreError::StoreCorrupt);
        }
        rows.insert(surface_row(&surface, receipt, seq)?);
    }
    rows.insert(SearchProjectionRow::checkpoint(frontier));
    Ok(rows.into_iter().collect())
}

/// One staged entry of a keyed L0002 map. The row_id is kept only so the
/// original physical-order tie-breaks (first/last lexicographic row_id at an
/// equal sequence) stay explicit when rows no longer arrive in row_id order.
#[derive(Clone)]
struct Latest<V> {
    value: V,
    seq: u64,
    row_id: Box<str>,
}

impl<V> Latest<V> {
    fn new(value: V, seq: u64, row_id: &str) -> Self {
        Self {
            value,
            seq,
            row_id: row_id.into(),
        }
    }
}

/// Strictly-newer-sequence semantics of the original `latest` helper, made
/// explicit for arbitrary visit order: a strictly greater sequence wins; at an
/// equal sequence the first lexicographic row_id (the original physical read
/// order) wins.
fn latest_insert<K: Ord, V>(
    map: &mut BTreeMap<K, Latest<V>>,
    key: K,
    value: V,
    seq: u64,
    row_id: &str,
) {
    match map.get(&key) {
        Some(existing)
            if existing.seq > seq
                || (existing.seq == seq && existing.row_id.as_ref() <= row_id) => {}
        _ => {
            map.insert(key, Latest::new(value, seq, row_id));
        }
    }
}

/// The original unconditional map insertions selected the last visit in
/// lexicographic row_id order, independent of sequence; an equal row_id is a
/// later visit and replaces too.
fn replace_insert<K: Ord, V>(
    map: &mut BTreeMap<K, Latest<V>>,
    key: K,
    value: V,
    seq: u64,
    row_id: &str,
) {
    if map
        .get(&key)
        .is_none_or(|existing| row_id >= existing.row_id.as_ref())
    {
        map.insert(key, Latest::new(value, seq, row_id));
    }
}

/// The current-revision winner needs the strictly-newest sequence; at an
/// equal sequence the first lexicographic row_id wins, as in the original
/// physical read order.
fn current_revision_insert(
    map: &mut BTreeMap<String, (u64, String, Box<str>)>,
    object_id: &str,
    revision_id: &str,
    seq: u64,
    row_id: &str,
) {
    match map.get(object_id) {
        Some((existing_seq, _, existing_row))
            if *existing_seq > seq || (*existing_seq == seq && existing_row.as_ref() <= row_id) => {
        }
        _ => {
            map.insert(
                object_id.to_owned(),
                (seq, revision_id.to_owned(), row_id.into()),
            );
        }
    }
}

fn latest_values<K: Ord, V: Clone>(map: &BTreeMap<K, Latest<V>>) -> Vec<V> {
    map.values().map(|entry| entry.value.clone()).collect()
}

/// The private L0002 accumulator: the concrete local maps and algorithms of
/// the original whole-snapshot derive moved into one consume/finish owner.
/// Rows are consumed exactly once; evaluation that needs future facts (Wiki
/// source atoms and exact-identifier currentness) is deferred to `finish`,
/// never buffered as raw rows.
#[derive(Default)]
pub(crate) struct L0002RowAccumulator {
    staged_wiki_atom: Option<StoreError>,
    staged_filter: Option<StoreError>,
    staged_body: Option<StoreError>,
    checkpoint_count: usize,
    checkpoint_seq: Option<u64>,
    max_data_seq: u64,
    wiki_atoms_by_revision: BTreeMap<RevisionId, Atom>,
    current_revisions: BTreeMap<String, (u64, String, Box<str>)>,
    receipts: BTreeMap<SourceReceiptId, Latest<SourceReceipt>>,
    surfaces: BTreeMap<SourceObservationId, Latest<EvidenceSurface>>,
    occurrences: BTreeMap<HostOccurrenceId, Latest<HostOccurrence>>,
    operations: BTreeMap<OperationId, Latest<Operation>>,
    effects: BTreeMap<ScopeEffectId, Latest<ScopeEffect>>,
    repositories: BTreeMap<RepositoryId, Latest<RepositoryInstance>>,
    worktrees: BTreeMap<WorktreeId, Latest<WorktreeInstance>>,
    snapshots: BTreeMap<WorktreeSnapshotId, Latest<WorktreeSnapshot>>,
    transitions: BTreeMap<WorktreeTransitionId, Latest<WorktreeTransition>>,
    integrations: BTreeMap<IntegrationEventId, Latest<IntegrationEvent>>,
    tasks: BTreeMap<TaskId, Latest<Task>>,
    workstreams: BTreeMap<WorkstreamId, Latest<Workstream>>,
    bindings: BTreeMap<WorkBindingRevisionId, Latest<WorkBindingRevision>>,
    attempts: BTreeMap<AttemptId, Latest<Attempt>>,
    groups: BTreeMap<CompetingAttemptGroupId, Latest<CompetingAttemptGroup>>,
    lanes: BTreeMap<ExecutionLaneId, Latest<ExecutionLane>>,
    capture_receipts: BTreeMap<ExecutionLaneId, Latest<CaptureReceipt>>,
    bursts: BTreeMap<OperationBurstId, Latest<OperationBurst>>,
    episodes: BTreeMap<WorkEpisodeId, Latest<WorkEpisode>>,
    checkpoints: BTreeMap<String, Latest<WorkCheckpoint>>,
    corrections: BTreeMap<RevisionId, Latest<SegmentationCorrection>>,
    recovery_requests: BTreeMap<RecoveryCaptureRequestId, Latest<RecoveryCaptureRequest>>,
    recovery_bundles: BTreeMap<RecoveryBundleId, Latest<RecoveryBundle>>,
    recovery_applications: BTreeMap<RecoveryApplicationId, Latest<RecoveryApplication>>,
    runs: BTreeMap<ExperimentRunId, Latest<ExperimentRun>>,
    results: BTreeMap<ResultEvidenceId, Latest<ResultEvidence>>,
    artifacts: BTreeMap<WorkArtifactId, Latest<WorkArtifact>>,
    atoms: BTreeMap<RevisionId, Latest<Atom>>,
    proposals: BTreeMap<RevisionId, Latest<RevisionProposal>>,
    procedures: BTreeMap<RevisionId, Latest<ProcedureRevision>>,
    procedure_usages: BTreeMap<ProcedureUsageId, Latest<ProcedureUsageRevision>>,
    procedure_negatives: BTreeMap<ProcedureNegativeEvidenceId, Latest<ProcedureNegativeEvidence>>,
    procedure_reviews: BTreeMap<ProcedureNegativeEvidenceId, Latest<ProcedureNegativeReviewEvent>>,
    core_memberships: BTreeMap<RevisionId, Latest<CoreMembership>>,
    support_contracts: BTreeMap<RevisionId, Latest<GlobalSuccessorSupportContract>>,
    deferred_wiki: Vec<(WikiProjection, u64, Box<str>)>,
    deferred_exact: Vec<DeferredExact>,
    semantic_digests: Vec<SemanticDigest>,
    wiki_projections: Vec<WikiProjection>,
    exact_rows: BTreeMap<String, (SearchProjectionRow, Box<str>)>,
    endpoint_seqs: BTreeMap<String, u64>,
}

struct DeferredExact {
    candidate: SearchProjectionRow,
    object_id: String,
    current_revision_id: Option<String>,
    source_row_id: Box<str>,
}

impl L0002RowAccumulator {
    /// Consume one canonical objects row. Never fails: the first error of
    /// each original pass class is staged so a paged physical read that
    /// discovers a later native failure still takes precedence. Callers that
    /// need immediate failure semantics use `finish`'s staged reporting.
    pub(crate) fn consume_row(&mut self, row: &ObjectRow) {
        if let Err(error) = self.consume_row_inner(row) {
            self.stage_classed(ConsumeClass::Body, error);
        }
    }

    /// The first staged error of each original pass class, or the first
    /// immediate error. Error classes follow the original pass order: the
    /// Wiki atom pre-pass, then the shared per-row filters, then the body.
    fn stage_classed(&mut self, class: ConsumeClass, error: StoreError) {
        let slot = match class {
            ConsumeClass::WikiAtom => &mut self.staged_wiki_atom,
            ConsumeClass::Filter => &mut self.staged_filter,
            ConsumeClass::Body => &mut self.staged_body,
        };
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    fn consume_row_inner(&mut self, row: &ObjectRow) -> Result<(), StoreError> {
        if row.row_kind != ObjectRowKind::Data {
            if row.row_kind == ObjectRowKind::Checkpoint {
                self.checkpoint_count += 1;
                self.checkpoint_seq = Some(row.source_event_seq);
            }
            return Ok(());
        }
        self.max_data_seq = self.max_data_seq.max(row.source_event_seq);
        if self.staged_wiki_atom.is_none()
            && let Err(error) = self.consume_wiki_atom(row)
        {
            self.stage_classed(ConsumeClass::WikiAtom, error);
        }
        if self.staged_filter.is_some() {
            return Ok(());
        }
        let wiki = match self.consume_filters(row) {
            Ok(FilterOutcome::Skipped) => return Ok(()),
            Ok(FilterOutcome::Accepted { wiki }) => wiki,
            Err(error) => {
                self.stage_classed(ConsumeClass::Filter, error);
                return Ok(());
            }
        };
        self.consume_body(row, wiki)
    }

    /// The original Wiki pre-pass: historical Atom revisions indexed by
    /// revision for the deferred Wiki evaluation.
    fn consume_wiki_atom(&mut self, row: &ObjectRow) -> Result<(), StoreError> {
        if row.object_kind.as_deref() != Some("atom_revision") {
            return Ok(());
        }
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        let JournalPayload::AtomRecorded(atom) = payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if row.object_id.as_deref() != Some(&atom.atom_id.to_string())
            || row.current_revision_id.as_deref() != Some(&atom.revision_id.to_string())
            || self
                .wiki_atoms_by_revision
                .insert(atom.revision_id, *atom)
                .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    /// The original two filter passes with their exact short-circuit order.
    /// A row skipped by the first pass never reaches the current-revision or
    /// body passes; a Wiki row still runs the second pass's effect/restore
    /// checks before its deferred body.
    fn consume_filters(&mut self, row: &ObjectRow) -> Result<FilterOutcome, StoreError> {
        let mut wiki = None;
        if recall_trigger_contract(row)?.is_some()
            || recall_need(row)?.is_some()
            || l3_core_projection(row)?
        {
            return Ok(FilterOutcome::Skipped);
        }
        match wiki_projection(row)? {
            Some(value) => wiki = Some(value),
            None => {
                if procedure_context_effect(row)?.is_some()
                    || crate::session_import::restore_current(row)?.is_some()
                {
                    return Ok(FilterOutcome::Skipped);
                }
                // The original first pass accepted the row: collect its
                // current revision with the strictly-newer-sequence rule.
                if let (Some(object_id), Some(revision_id)) =
                    (row.object_id.as_ref(), row.current_revision_id.as_ref())
                {
                    current_revision_insert(
                        &mut self.current_revisions,
                        object_id,
                        revision_id,
                        row.source_event_seq,
                        &row.row_id,
                    );
                }
                return Ok(FilterOutcome::Accepted { wiki });
            }
        }
        // The Wiki row: the original second pass re-checked the non-Wiki
        // chain (all known None above) and evaluated effect/restore before
        // its Wiki branch.
        if procedure_context_effect(row)?.is_some()
            || crate::session_import::restore_current(row)?.is_some()
        {
            return Ok(FilterOutcome::Skipped);
        }
        Ok(FilterOutcome::Accepted { wiki })
    }

    /// The original second-pass body for one non-Wiki row: endpoint sequence
    /// index, the keyed family maps, and the deferred exact-identifier row.
    fn consume_body(
        &mut self,
        row: &ObjectRow,
        wiki: Option<WikiProjection>,
    ) -> Result<(), StoreError> {
        if let Some(wiki) = wiki {
            self.deferred_wiki
                .push((wiki, row.source_event_seq, row.row_id.clone().into()));
            return Ok(());
        }
        for endpoint in [row.object_id.as_ref(), row.current_revision_id.as_ref()]
            .into_iter()
            .flatten()
        {
            self.endpoint_seqs
                .entry(endpoint.clone())
                .and_modify(|seq| *seq = (*seq).max(row.source_event_seq))
                .or_insert(row.source_event_seq);
        }
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        index_typed_ids(&payload, row.source_event_seq, &mut self.endpoint_seqs)?;
        match payload {
            JournalPayload::SourceReceiptRecorded(value) => latest_insert(
                &mut self.receipts,
                value.source_receipt_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::EvidenceSurfaceRecorded(value) => latest_insert(
                &mut self.surfaces,
                value.source_observation_revision_ref,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::HostOccurrenceNormalized(value) => latest_insert(
                &mut self.occurrences,
                value.host_occurrence_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::OperationDerived(value) => latest_insert(
                &mut self.operations,
                value.operation_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ScopeEffectDerived(value) => latest_insert(
                &mut self.effects,
                value.scope_effect_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::RepositoryInstanceRecorded(value) => latest_insert(
                &mut self.repositories,
                value.repository_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorktreeInstanceRecorded(value) => latest_insert(
                &mut self.worktrees,
                value.worktree_instance_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorktreeSnapshotRecorded(value) => latest_insert(
                &mut self.snapshots,
                value.worktree_snapshot_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorktreeTransitionRecorded(value) => latest_insert(
                &mut self.transitions,
                value.worktree_transition_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::IntegrationEventRecorded(value) => latest_insert(
                &mut self.integrations,
                value.integration_event_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::TaskRecorded(value) => latest_insert(
                &mut self.tasks,
                value.task_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorkstreamRecorded(value) => latest_insert(
                &mut self.workstreams,
                value.workstream_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorkBindingRecorded(value) => latest_insert(
                &mut self.bindings,
                value.work_binding_revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::AttemptRecorded(value) => latest_insert(
                &mut self.attempts,
                value.attempt_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::CompetingAttemptGroupRecorded(value) => latest_insert(
                &mut self.groups,
                value.competing_group_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ExecutionLaneRecorded(value) => latest_insert(
                &mut self.lanes,
                value.execution_lane_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::CaptureReceiptRecorded(value) => latest_insert(
                &mut self.capture_receipts,
                value.execution_lane_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::OperationBurstRecorded(value) => latest_insert(
                &mut self.bursts,
                value.operation_burst_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorkEpisodeRecorded(value) => latest_insert(
                &mut self.episodes,
                value.episode_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorkCheckpointRecorded(value) => latest_insert(
                &mut self.checkpoints,
                value.stable_key(),
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::SegmentationCorrectionRecorded(value) => replace_insert(
                &mut self.corrections,
                value.correction_revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::RecoveryCaptureRequestRecorded(value) => latest_insert(
                &mut self.recovery_requests,
                value.recovery_capture_request_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::RecoveryBundleRecorded(value) => latest_insert(
                &mut self.recovery_bundles,
                value.recovery_bundle_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::RecoveryApplicationRecorded(value) => latest_insert(
                &mut self.recovery_applications,
                value.recovery_application_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ExperimentRunRecorded(value) => latest_insert(
                &mut self.runs,
                value.run_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ResultEvidenceRecorded(value) => latest_insert(
                &mut self.results,
                value.result_evidence_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::WorkArtifactRecorded(value) => latest_insert(
                &mut self.artifacts,
                value.work_artifact_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::AtomRecorded(value) => replace_insert(
                &mut self.atoms,
                value.revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::RevisionProposalRecorded(value) => replace_insert(
                &mut self.proposals,
                value.proposal_revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ProcedureRevisionRecorded(value) => replace_insert(
                &mut self.procedures,
                value.revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ProcedureUsageRecorded(value) => latest_insert(
                &mut self.procedure_usages,
                value.procedure_usage_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => latest_insert(
                &mut self.procedure_negatives,
                value.negative_evidence_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::ProcedureNegativeReviewRecorded(value) => latest_insert(
                &mut self.procedure_reviews,
                value.negative_evidence_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::CoreMembershipRecorded(value) => replace_insert(
                &mut self.core_memberships,
                value.membership_revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::GlobalSupportContractRecorded(value) => replace_insert(
                &mut self.support_contracts,
                value.support_contract_revision_id,
                *value,
                row.source_event_seq,
                &row.row_id,
            ),
            JournalPayload::SemanticDigestRecorded(value) => {
                self.semantic_digests.push(*value);
            }
            _ => {}
        }
        // Exact-identifier candidacy needs the final currentness, so only the
        // is_current-independent part is built now; `finish` sets currentness.
        if let Some(object_id) = row.object_id.as_ref()
            && let Some(candidate) = exact_identifier_row(row, row.source_event_seq, false)?
        {
            self.deferred_exact.push(DeferredExact {
                candidate,
                object_id: object_id.clone(),
                current_revision_id: row.current_revision_id.clone(),
                source_row_id: row.row_id.clone().into(),
            });
        }
        Ok(())
    }

    /// Finish relations/search from the consumed state. Header checks and
    /// staged per-pass errors keep the original whole-snapshot derive's
    /// observable error order.
    pub(crate) fn finish(mut self, frontier: u64) -> Result<L0002ProjectionSnapshot, StoreError> {
        if self.checkpoint_count != 1
            || self.checkpoint_seq != Some(frontier)
            || self.max_data_seq > frontier
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(error) = self
            .staged_wiki_atom
            .or(self.staged_filter)
            .or(self.staged_body)
        {
            return Err(error);
        }
        // Deferred Wiki evaluation, exactly the original second-pass body.
        for (wiki, seq, row_id) in std::mem::take(&mut self.deferred_wiki) {
            let source_atoms = wiki
                .source_atom_ids
                .iter()
                .map(|atom_id| {
                    let (_, revision_id, _) = self
                        .current_revisions
                        .get(&atom_id.to_string())
                        .ok_or(StoreError::StoreCorrupt)?;
                    let revision_id = revision_id
                        .parse::<RevisionId>()
                        .map_err(|_| StoreError::StoreCorrupt)?;
                    let atom = self
                        .wiki_atoms_by_revision
                        .get(&revision_id)
                        .ok_or(StoreError::StoreCorrupt)?;
                    if atom.atom_id != *atom_id || atom.revision_id != revision_id {
                        return Err(StoreError::StoreCorrupt);
                    }
                    Ok(atom)
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            let (rendered_blob_ref, contradictions) =
                wiki_render_identity(&wiki.topic, &source_atoms, &wiki.source_episode_ids)?;
            if rendered_blob_ref != wiki.rendered_blob_ref {
                return Err(StoreError::StoreCorrupt);
            }
            let source_text =
                source_atoms
                    .iter()
                    .flat_map(|atom| {
                        let mut text = vec![
                            atom.value.subject.clone(),
                            atom.value.predicate.clone(),
                            atom.value.text.clone(),
                        ];
                        text.extend(atom.value.object.clone());
                        text.extend(atom.value.qualifiers.iter().flat_map(|qualifier| {
                            [qualifier.name.clone(), qualifier.value.clone()]
                        }));
                        text
                    })
                    .collect::<Vec<_>>();
            if source_text.is_empty() {
                return Err(StoreError::StoreCorrupt);
            }
            let candidate = wiki_search_row(&wiki, &source_text, &contradictions, seq);
            self.exact_insert(candidate, &row_id);
            self.endpoint_seqs.insert(wiki.page_id.to_string(), seq);
            self.wiki_projections.push(wiki);
        }
        // Exact-identifier currentness is finalized only now that the winning
        // revision per object id is known.
        for deferred in std::mem::take(&mut self.deferred_exact) {
            let mut candidate = deferred.candidate;
            let is_current =
                self.current_revisions
                    .get(&deferred.object_id)
                    .is_some_and(|(_, revision, _)| {
                        deferred.current_revision_id.as_ref() == Some(revision)
                    });
            candidate.currentness = Some(if is_current { "current" } else { "historical" }.into());
            self.exact_insert(candidate, &deferred.source_row_id);
        }
        self.finish_relations_search(frontier)
    }

    /// The original unconditional exact-row insertion kept the candidate
    /// produced by the last row in lexicographic row_id order.
    fn exact_insert(&mut self, candidate: SearchProjectionRow, source_row_id: &str) {
        if self
            .exact_rows
            .get(&candidate.row_id)
            .is_none_or(|(_, existing)| source_row_id > existing.as_ref())
        {
            self.exact_rows
                .insert(candidate.row_id.clone(), (candidate, source_row_id.into()));
        }
    }

    fn finish_relations_search(self, frontier: u64) -> Result<L0002ProjectionSnapshot, StoreError> {
        let available_atom_revisions = self.atoms.keys().copied().collect::<BTreeSet<_>>();
        let available_procedure_revisions =
            self.procedures.keys().copied().collect::<BTreeSet<_>>();
        let relation_atoms = latest_values(&self.atoms)
            .into_iter()
            .map(|mut atom| {
                atom.parent_revision_id = atom
                    .parent_revision_id
                    .filter(|revision| available_atom_revisions.contains(revision));
                atom.supersedes_revision_refs
                    .retain(|revision| available_atom_revisions.contains(revision));
                atom.supports_revision_refs
                    .retain(|revision| available_atom_revisions.contains(revision));
                atom.contradicts_revision_refs
                    .retain(|revision| available_atom_revisions.contains(revision));
                atom
            })
            .collect::<Vec<_>>();
        let relation_procedures = latest_values(&self.procedures)
            .into_iter()
            .map(|mut procedure| {
                procedure.parent_revision_id = procedure
                    .parent_revision_id
                    .filter(|revision| available_procedure_revisions.contains(revision));
                procedure
                    .draft
                    .support_revision_refs
                    .retain(|revision| available_atom_revisions.contains(revision));
                procedure
            })
            .collect::<Vec<_>>();
        let mut relations = BTreeSet::new();
        add_physical(
            &mut relations,
            build_physical_relation_rows(
                &latest_values(&self.occurrences),
                &latest_values(&self.operations),
                &latest_values(&self.effects),
            )?,
            &self.endpoint_seqs,
        );
        add_repository(
            &mut relations,
            build_repository_relation_rows(
                &latest_values(&self.repositories),
                &latest_values(&self.worktrees),
                &latest_values(&self.snapshots),
                &latest_values(&self.transitions),
                &latest_values(&self.integrations),
            )?,
            &self.endpoint_seqs,
        );
        add_work_identity(
            &mut relations,
            build_work_identity_relation_rows(
                &latest_values(&self.tasks),
                &latest_values(&self.workstreams),
            )?,
            &self.endpoint_seqs,
        );
        add_attempt(
            &mut relations,
            build_attempt_relation_rows(
                &latest_values(&self.attempts),
                &latest_values(&self.groups),
            )?,
            &self.endpoint_seqs,
        );
        add_work_binding(
            &mut relations,
            build_work_binding_relation_rows(
                &latest_values(&self.bindings),
                &latest_values(&self.operations),
                &latest_values(&self.effects),
                &latest_values(&self.tasks),
                &latest_values(&self.workstreams),
            )?,
            &self.endpoint_seqs,
        );
        add_episode(
            &mut relations,
            build_episode_relation_rows(
                &latest_values(&self.episodes),
                &latest_values(&self.checkpoints),
            )?,
            &self.endpoint_seqs,
        );
        for (lane_id, lane) in &self.lanes {
            let receipt = self
                .capture_receipts
                .get(lane_id)
                .ok_or(StoreError::StoreCorrupt)?;
            add_capture(
                &mut relations,
                build_capture_relation_rows(&lane.value, &receipt.value)?,
                &self.endpoint_seqs,
            );
        }
        add_burst(
            &mut relations,
            build_operation_burst_relation_rows(
                &latest_values(&self.episodes),
                &latest_values(&self.bursts),
            )?,
            &self.endpoint_seqs,
        );
        add_correction(
            &mut relations,
            build_segmentation_correction_relation_rows(
                &latest_values(&self.corrections),
                &latest_values(&self.episodes),
            )?,
            &self.endpoint_seqs,
        );
        add_recovery(
            &mut relations,
            build_recovery_relation_rows(
                &latest_values(&self.recovery_requests),
                &latest_values(&self.recovery_bundles),
            )?,
            &self.endpoint_seqs,
        );
        add_recovery(
            &mut relations,
            build_recovery_application_relation_rows(&latest_values(&self.recovery_applications))?,
            &self.endpoint_seqs,
        );
        add_autoresearch(
            &mut relations,
            build_autoresearch_relation_rows(
                &latest_values(&self.runs),
                &latest_values(&self.results),
                &latest_values(&self.artifacts),
            )?,
            &self.endpoint_seqs,
        );
        add_semantic(
            &mut relations,
            build_semantic_relation_rows(&relation_atoms, &latest_values(&self.proposals))?,
            &self.endpoint_seqs,
        );
        add_semantic(
            &mut relations,
            build_wiki_relation_rows(&self.wiki_projections)?,
            &self.endpoint_seqs,
        );
        add_semantic(
            &mut relations,
            build_semantic_digest_relation_rows(&self.semantic_digests)?,
            &self.endpoint_seqs,
        );
        add_semantic(
            &mut relations,
            build_procedure_relation_rows(&relation_procedures, &relation_atoms)?,
            &self.endpoint_seqs,
        );
        add_semantic(
            &mut relations,
            build_procedure_usage_relation_rows(
                &latest_values(&self.procedure_usages),
                &latest_values(&self.procedure_negatives),
                &latest_values(&self.procedure_reviews),
            )?,
            &self.endpoint_seqs,
        );
        add_semantic(
            &mut relations,
            build_core_support_relation_rows(
                &latest_values(&self.core_memberships),
                &latest_values(&self.support_contracts),
            )?,
            &self.endpoint_seqs,
        );
        relations.insert(RelationProjectionRow::checkpoint(frontier));

        let mut search = self
            .exact_rows
            .into_values()
            .map(|(candidate, _)| candidate)
            .collect::<BTreeSet<_>>();
        let mut receipts_by_observation = BTreeMap::new();
        for receipt in self.receipts.values() {
            receipts_by_observation
                .entry(receipt.value.source_observation_id)
                .or_insert(&receipt.value);
        }
        for (revision_ref, surface) in &self.surfaces {
            let receipt = receipts_by_observation
                .get(revision_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            search.insert(surface_row(&surface.value, receipt, surface.seq)?);
        }
        search.insert(SearchProjectionRow::checkpoint(frontier));
        Ok(L0002ProjectionSnapshot {
            frontier,
            relations: relations.into_iter().collect(),
            search: search.into_iter().collect(),
        })
    }
}

enum ConsumeClass {
    WikiAtom,
    Filter,
    Body,
}

enum FilterOutcome {
    Skipped,
    Accepted { wiki: Option<WikiProjection> },
}

/// The complete whole-snapshot derivation, now the thin complete-path driver
/// over the one private accumulator. Public complete callers keep the exact
/// original behavior and results.
pub fn derive_l0002_projections(
    objects: &ProjectionSnapshot,
) -> Result<L0002ProjectionSnapshot, StoreError> {
    let mut accumulator = L0002RowAccumulator::default();
    for row in &objects.rows {
        accumulator.consume_row(row);
    }
    accumulator.finish(objects.frontier)
}

// The merge source contains only changed rows. Deletion must name only rows
// absent from the complete expected projection, never unchanged target rows.
fn deleted_row_predicate(removed: &[&str]) -> String {
    let ids = removed
        .iter()
        .map(|id| format!("'{}'", id.replace('\'', "''")))
        .collect::<Vec<_>>();
    format!("row_id IN ({})", ids.join(","))
}

fn commit_relation_rows(
    state: &SqliteHandle,
    current: &[RelationProjectionRow],
    rows: &[RelationProjectionRow],
) -> Result<(), StoreError> {
    if current == rows {
        return Ok(());
    }
    let previous = current
        .iter()
        .map(|row| (&row.row_id, row))
        .collect::<BTreeMap<_, _>>();
    let expected = rows.iter().map(|row| &row.row_id).collect::<BTreeSet<_>>();
    let changed = rows
        .iter()
        .filter(|row| previous.get(&row.row_id).copied() != Some(*row))
        .cloned()
        .collect::<Vec<_>>();
    let removed = current
        .iter()
        .filter(|row| !expected.contains(&row.row_id))
        .map(|row| row.row_id.clone())
        .collect::<Vec<_>>();
    let checkpoint = rows
        .iter()
        .find(|row| row.row_id == crate::relations::RELATIONS_CHECKPOINT_ID)
        .ok_or(StoreError::StoreCorrupt)?;
    state
        .lock()
        .map_err(|_| StoreError::StoreCorrupt)?
        .commit_relation_rows(&changed, &removed, checkpoint)
}
async fn commit_search_rows(
    table: &Table,
    current: &[SearchProjectionRow],
    rows: &[SearchProjectionRow],
    fail_before_execute: bool,
) -> Result<(), StoreError> {
    if current == rows {
        return Ok(());
    }
    let previous = current
        .iter()
        .map(|row| (&row.row_id, row))
        .collect::<BTreeMap<_, _>>();
    let expected = rows.iter().map(|row| &row.row_id).collect::<BTreeSet<_>>();
    let changed = rows
        .iter()
        .filter(|row| previous.get(&row.row_id).copied() != Some(*row))
        .cloned()
        .collect::<Vec<_>>();
    let removed = current
        .iter()
        .filter(|row| !expected.contains(&row.row_id))
        .map(|row| row.row_id.as_str())
        .collect::<Vec<_>>();
    let reader = Box::new(RecordBatchIterator::new(
        vec![Ok(search_batch(&changed)?)],
        crate::search::search_schema(),
    ));
    let mut merge = table.merge_insert(&["row_id"]);
    merge
        .when_matched_update_all(None)
        .when_not_matched_insert_all();
    if !removed.is_empty() {
        merge.when_not_matched_by_source_delete(Some(deleted_row_predicate(&removed)));
    }
    if fail_before_execute {
        return Err(StoreError::Projection);
    }
    merge
        .execute(reader)
        .await
        .map_err(|_| StoreError::Projection)?;
    Ok(())
}
pub(super) fn checkpoint_relation(rows: &[RelationProjectionRow]) -> Result<u64, StoreError> {
    rows.iter()
        .find(|row| row.row_id == crate::relations::RELATIONS_CHECKPOINT_ID)
        .map(|row| row.source_event_seq)
        .ok_or(StoreError::StoreCorrupt)
}
pub(super) fn checkpoint_search(rows: &[SearchProjectionRow]) -> Result<u64, StoreError> {
    rows.iter()
        .find(|row| row.row_id == crate::search::SEARCH_CHECKPOINT_ID)
        .map(|row| row.source_event_seq)
        .ok_or(StoreError::StoreCorrupt)
}
fn relation_values(rows: &[RelationProjectionRow]) -> CanonicalValue {
    CanonicalValue::Sequence(
        rows.iter()
            .map(|row| {
                CanonicalValue::Sequence(vec![
                    CanonicalValue::String(row.row_id.clone()),
                    CanonicalValue::String(row.relation_kind.clone().unwrap_or_default()),
                    CanonicalValue::String(row.source_id.clone().unwrap_or_default()),
                    CanonicalValue::String(row.target_id.clone().unwrap_or_default()),
                    CanonicalValue::Integer(i128::from(row.source_event_seq)),
                    CanonicalValue::Integer(i128::from(row.projection_generation)),
                ])
            })
            .collect(),
    )
}
fn search_values(rows: &[SearchProjectionRow]) -> CanonicalValue {
    CanonicalValue::Sequence(
        rows.iter()
            .map(|row| {
                CanonicalValue::Sequence(vec![
                    CanonicalValue::String(row.row_id.clone()),
                    CanonicalValue::String(row.row_variant.clone()),
                    CanonicalValue::String(row.candidate_id.clone().unwrap_or_default()),
                    CanonicalValue::String(row.source_ref.clone().unwrap_or_default()),
                    CanonicalValue::String(row.source_kind.clone().unwrap_or_default()),
                    CanonicalValue::String(row.text.clone()),
                    CanonicalValue::String(row.source_role.clone().unwrap_or_default()),
                    CanonicalValue::String(row.content_trust.clone().unwrap_or_default()),
                    CanonicalValue::String(row.capture_completeness.clone().unwrap_or_default()),
                    CanonicalValue::String(row.instruction_authority.clone()),
                    CanonicalValue::String(row.object_kind.clone().unwrap_or_default()),
                    CanonicalValue::String(row.currentness.clone().unwrap_or_default()),
                    CanonicalValue::String(row.lifecycle.clone().unwrap_or_default()),
                    CanonicalValue::String(row.epistemic.clone().unwrap_or_default()),
                    CanonicalValue::String(row.authority.clone().unwrap_or_default()),
                    CanonicalValue::String(row.task_id.clone().unwrap_or_default()),
                    CanonicalValue::String(row.repository_id.clone().unwrap_or_default()),
                    CanonicalValue::String(row.worktree_id.clone().unwrap_or_default()),
                    CanonicalValue::Integer(i128::from(row.event_time_us)),
                    CanonicalValue::Integer(i128::from(row.recorded_at_us)),
                    CanonicalValue::Integer(i128::from(row.source_sequence)),
                    CanonicalValue::String(row.time_domain.clone()),
                    CanonicalValue::String(row.retrieval_completeness.clone()),
                    CanonicalValue::String(row.suppression_ref_hash.clone().unwrap_or_default()),
                    CanonicalValue::Integer(i128::from(row.source_event_seq)),
                    CanonicalValue::Integer(i128::from(row.projection_generation)),
                ])
            })
            .collect(),
    )
}
fn canonical_hash(tag: &str, value: CanonicalValue) -> Result<[u8; 32], StoreError> {
    sha256(tag, 1, &value).map_err(|_| StoreError::StoreCorrupt)
}

fn option(value: Option<String>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, CanonicalValue::String)
}

#[cfg(test)]
include!("tests.rs");
