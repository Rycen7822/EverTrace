//! L0002 projection workers over one validated L0001 object frontier.

use std::collections::{BTreeMap, BTreeSet};

use arrow_array::RecordBatchIterator;
use evertrace_domain::canonical::{CanonicalValue, sha256};
use lancedb::Table;

use crate::{
    JournalPayload, ObjectRowKind, ProjectionSnapshot, StoreError,
    journal::{read_journal_after, read_journal_frontier},
    projections::{recall_trigger_contract, validate_delta},
    relations::{
        RelationProjectionRow, build_attempt_relation_rows, build_autoresearch_relation_rows,
        build_capture_relation_rows, build_episode_relation_rows,
        build_operation_burst_relation_rows, build_physical_relation_rows,
        build_recovery_application_relation_rows, build_recovery_relation_rows,
        build_repository_relation_rows, build_segmentation_correction_relation_rows,
        build_semantic_relation_rows, build_work_binding_relation_rows,
        build_work_identity_relation_rows, read_relation_rows, relations_batch,
    },
    search::{SearchProjectionRow, read_search_rows, search_batch},
};

use super::derive::{exact_identifier_row, surface_row};
use super::relation_assembly::{
    add_attempt, add_autoresearch, add_burst, add_capture, add_correction, add_episode,
    add_physical, add_recovery, add_repository, add_semantic, add_work_binding, add_work_identity,
    index_typed_ids,
};

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
    journal: Table,
    relations: Table,
    search: Table,
}

impl L0002ProjectionWorker {
    pub(crate) fn new(journal: Table, relations: Table, search: Table) -> Self {
        Self {
            journal,
            relations,
            search,
        }
    }

    pub async fn catch_up(
        &self,
        objects: &ProjectionSnapshot,
    ) -> Result<L0002ProjectionSnapshot, StoreError> {
        self.catch_up_inner(objects, false, false).await
    }

    async fn catch_up_inner(
        &self,
        objects: &ProjectionSnapshot,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<L0002ProjectionSnapshot, StoreError> {
        let relations = read_relation_rows(&self.relations).await?;
        let search = read_search_rows(&self.search).await?;
        let relation_frontier = checkpoint_relation(&relations)?;
        let search_frontier = checkpoint_search(&search)?;
        let journal_frontier = read_journal_frontier(&self.journal).await?;
        if objects.frontier != journal_frontier
            || relation_frontier > journal_frontier
            || search_frontier > journal_frontier
        {
            return Err(StoreError::StoreCorrupt);
        }
        for checkpoint in [relation_frontier, search_frontier] {
            let delta = read_journal_after(&self.journal, checkpoint).await?;
            validate_delta(checkpoint, journal_frontier, &delta)?;
        }
        if relation_frontier == journal_frontier && search_frontier == journal_frontier {
            return Ok(L0002ProjectionSnapshot {
                frontier: journal_frontier,
                relations,
                search,
            });
        }
        let expected = derive_l0002_projections(objects)?;
        commit_relation_rows(&self.relations, &expected.relations, fail_relation_commit).await?;
        commit_search_rows(&self.search, &expected.search, fail_search_commit).await?;
        let persisted = L0002ProjectionSnapshot {
            frontier: expected.frontier,
            relations: read_relation_rows(&self.relations).await?,
            search: read_search_rows(&self.search).await?,
        };
        if persisted != expected {
            return Err(StoreError::Projection);
        }
        Ok(persisted)
    }

    #[cfg(test)]
    async fn catch_up_with_fault(
        &self,
        objects: &ProjectionSnapshot,
        fail_relation_commit: bool,
        fail_search_commit: bool,
    ) -> Result<L0002ProjectionSnapshot, StoreError> {
        self.catch_up_inner(objects, fail_relation_commit, fail_search_commit)
            .await
    }

    pub async fn current(&self) -> Result<L0002ProjectionSnapshot, StoreError> {
        let relations = read_relation_rows(&self.relations).await?;
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

pub fn derive_l0002_projections(
    objects: &ProjectionSnapshot,
) -> Result<L0002ProjectionSnapshot, StoreError> {
    if objects
        .rows
        .iter()
        .filter(|row| row.row_kind == ObjectRowKind::Checkpoint)
        .count()
        != 1
        || objects
            .rows
            .iter()
            .find(|row| row.row_kind == ObjectRowKind::Checkpoint)
            .is_none_or(|row| row.source_event_seq != objects.frontier)
        || objects
            .rows
            .iter()
            .any(|row| row.source_event_seq > objects.frontier)
    {
        return Err(StoreError::StoreCorrupt);
    }

    let mut receipts = BTreeMap::new();
    let mut surfaces = BTreeMap::new();
    let mut occurrences = BTreeMap::new();
    let mut operations = BTreeMap::new();
    let mut effects = BTreeMap::new();
    let mut repositories = BTreeMap::new();
    let mut worktrees = BTreeMap::new();
    let mut snapshots = BTreeMap::new();
    let mut transitions = BTreeMap::new();
    let mut integrations = BTreeMap::new();
    let mut tasks = BTreeMap::new();
    let mut workstreams = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    let mut attempts = BTreeMap::new();
    let mut groups = BTreeMap::new();
    let mut lanes = BTreeMap::new();
    let mut capture_receipts = BTreeMap::new();
    let mut bursts = BTreeMap::new();
    let mut episodes = BTreeMap::new();
    let mut checkpoints = BTreeMap::new();
    let mut corrections = BTreeMap::new();
    let mut recovery_requests = BTreeMap::new();
    let mut recovery_bundles = BTreeMap::new();
    let mut recovery_applications = BTreeMap::new();
    let mut runs = BTreeMap::new();
    let mut results = BTreeMap::new();
    let mut artifacts = BTreeMap::new();
    let mut atoms = BTreeMap::new();
    let mut proposals = BTreeMap::new();
    let mut exact_rows = BTreeMap::new();
    let mut endpoint_seqs = BTreeMap::<String, u64>::new();
    let mut current_revisions = BTreeMap::<String, (u64, String)>::new();
    for row in objects.data_rows() {
        if recall_trigger_contract(row)?.is_some() {
            continue;
        }
        if let (Some(object_id), Some(revision_id)) =
            (row.object_id.as_ref(), row.current_revision_id.as_ref())
            && current_revisions
                .get(object_id)
                .is_none_or(|(seq, _)| *seq < row.source_event_seq)
        {
            current_revisions.insert(
                object_id.clone(),
                (row.source_event_seq, revision_id.clone()),
            );
        }
    }

    for row in objects.data_rows() {
        if recall_trigger_contract(row)?.is_some() {
            continue;
        }
        for endpoint in [row.object_id.as_ref(), row.current_revision_id.as_ref()]
            .into_iter()
            .flatten()
        {
            endpoint_seqs
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
        index_typed_ids(&payload, row.source_event_seq, &mut endpoint_seqs)?;
        match payload {
            JournalPayload::SourceReceiptRecorded(value) => latest(
                &mut receipts,
                value.source_receipt_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::EvidenceSurfaceRecorded(value) => latest(
                &mut surfaces,
                value.source_observation_revision_ref,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::HostOccurrenceNormalized(value) => latest(
                &mut occurrences,
                value.host_occurrence_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::OperationDerived(value) => latest(
                &mut operations,
                value.operation_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::ScopeEffectDerived(value) => latest(
                &mut effects,
                value.scope_effect_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::RepositoryInstanceRecorded(value) => latest(
                &mut repositories,
                value.repository_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorktreeInstanceRecorded(value) => latest(
                &mut worktrees,
                value.worktree_instance_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorktreeSnapshotRecorded(value) => latest(
                &mut snapshots,
                value.worktree_snapshot_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorktreeTransitionRecorded(value) => latest(
                &mut transitions,
                value.worktree_transition_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::IntegrationEventRecorded(value) => latest(
                &mut integrations,
                value.integration_event_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::TaskRecorded(value) => {
                latest(&mut tasks, value.task_id, *value, row.source_event_seq)
            }
            JournalPayload::WorkstreamRecorded(value) => latest(
                &mut workstreams,
                value.workstream_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorkBindingRecorded(value) => latest(
                &mut bindings,
                value.work_binding_revision_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::AttemptRecorded(value) => latest(
                &mut attempts,
                value.attempt_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::CompetingAttemptGroupRecorded(value) => latest(
                &mut groups,
                value.competing_group_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::ExecutionLaneRecorded(value) => latest(
                &mut lanes,
                value.execution_lane_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::CaptureReceiptRecorded(value) => latest(
                &mut capture_receipts,
                value.execution_lane_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::OperationBurstRecorded(value) => latest(
                &mut bursts,
                value.operation_burst_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorkEpisodeRecorded(value) => latest(
                &mut episodes,
                value.episode_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorkCheckpointRecorded(value) => latest(
                &mut checkpoints,
                value.stable_key(),
                *value,
                row.source_event_seq,
            ),
            JournalPayload::SegmentationCorrectionRecorded(value) => {
                corrections.insert(value.correction_revision_id, (*value, row.source_event_seq));
            }
            JournalPayload::RecoveryCaptureRequestRecorded(value) => latest(
                &mut recovery_requests,
                value.recovery_capture_request_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::RecoveryBundleRecorded(value) => latest(
                &mut recovery_bundles,
                value.recovery_bundle_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::RecoveryApplicationRecorded(value) => latest(
                &mut recovery_applications,
                value.recovery_application_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::ExperimentRunRecorded(value) => {
                latest(&mut runs, value.run_id, *value, row.source_event_seq)
            }
            JournalPayload::ResultEvidenceRecorded(value) => latest(
                &mut results,
                value.result_evidence_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::WorkArtifactRecorded(value) => latest(
                &mut artifacts,
                value.work_artifact_id,
                *value,
                row.source_event_seq,
            ),
            JournalPayload::AtomRecorded(value) => {
                atoms.insert(value.revision_id, (*value, row.source_event_seq));
            }
            JournalPayload::RevisionProposalRecorded(value) => {
                proposals.insert(value.proposal_revision_id, (*value, row.source_event_seq));
            }
            _ => {}
        }
        let is_current = row.object_id.as_ref().is_some_and(|object_id| {
            current_revisions
                .get(object_id)
                .is_some_and(|(_, revision)| row.current_revision_id.as_ref() == Some(revision))
        });
        if let Some(candidate) = exact_identifier_row(row, row.source_event_seq, is_current)? {
            exact_rows.insert(candidate.row_id.clone(), candidate);
        }
    }

    let mut relations = BTreeSet::new();
    add_physical(
        &mut relations,
        build_physical_relation_rows(
            &values(&occurrences),
            &values(&operations),
            &values(&effects),
        )?,
        &endpoint_seqs,
    );
    add_repository(
        &mut relations,
        build_repository_relation_rows(
            &values(&repositories),
            &values(&worktrees),
            &values(&snapshots),
            &values(&transitions),
            &values(&integrations),
        )?,
        &endpoint_seqs,
    );
    add_work_identity(
        &mut relations,
        build_work_identity_relation_rows(&values(&tasks), &values(&workstreams))?,
        &endpoint_seqs,
    );
    add_attempt(
        &mut relations,
        build_attempt_relation_rows(&values(&attempts), &values(&groups))?,
        &endpoint_seqs,
    );
    add_work_binding(
        &mut relations,
        build_work_binding_relation_rows(
            &values(&bindings),
            &values(&operations),
            &values(&effects),
            &values(&tasks),
            &values(&workstreams),
        )?,
        &endpoint_seqs,
    );
    add_episode(
        &mut relations,
        build_episode_relation_rows(&values(&episodes), &values(&checkpoints))?,
        &endpoint_seqs,
    );
    for (lane_id, (lane, _)) in &lanes {
        let receipt = capture_receipts
            .get(lane_id)
            .ok_or(StoreError::StoreCorrupt)?;
        add_capture(
            &mut relations,
            build_capture_relation_rows(lane, &receipt.0)?,
            &endpoint_seqs,
        );
    }
    add_burst(
        &mut relations,
        build_operation_burst_relation_rows(&values(&episodes), &values(&bursts))?,
        &endpoint_seqs,
    );
    add_correction(
        &mut relations,
        build_segmentation_correction_relation_rows(&all_values(&corrections), &values(&episodes))?,
        &endpoint_seqs,
    );
    add_recovery(
        &mut relations,
        build_recovery_relation_rows(&values(&recovery_requests), &values(&recovery_bundles))?,
        &endpoint_seqs,
    );
    add_recovery(
        &mut relations,
        build_recovery_application_relation_rows(&values(&recovery_applications))?,
        &endpoint_seqs,
    );
    add_autoresearch(
        &mut relations,
        build_autoresearch_relation_rows(&values(&runs), &values(&results), &values(&artifacts))?,
        &endpoint_seqs,
    );
    add_semantic(
        &mut relations,
        build_semantic_relation_rows(&all_values(&atoms), &all_values(&proposals))?,
        &endpoint_seqs,
    );
    relations.insert(RelationProjectionRow::checkpoint(objects.frontier));

    let mut search = exact_rows.into_values().collect::<BTreeSet<_>>();
    for (observation_id, (surface, seq)) in surfaces {
        let receipt = receipts
            .values()
            .find_map(|(value, _)| (value.source_observation_id == observation_id).then_some(value))
            .ok_or(StoreError::StoreCorrupt)?;
        search.insert(surface_row(&surface, receipt, seq)?);
    }
    search.insert(SearchProjectionRow::checkpoint(objects.frontier));
    Ok(L0002ProjectionSnapshot {
        frontier: objects.frontier,
        relations: relations.into_iter().collect(),
        search: search.into_iter().collect(),
    })
}

fn latest<K: Ord, V>(map: &mut BTreeMap<K, (V, u64)>, key: K, value: V, seq: u64) {
    if map.get(&key).is_none_or(|(_, current)| *current < seq) {
        map.insert(key, (value, seq));
    }
}
fn values<K, V: Clone>(map: &BTreeMap<K, (V, u64)>) -> Vec<V> {
    map.values().map(|(value, _)| value.clone()).collect()
}
fn all_values<K, V: Clone>(map: &BTreeMap<K, (V, u64)>) -> Vec<V> {
    values(map)
}

async fn commit_relation_rows(
    table: &Table,
    rows: &[RelationProjectionRow],
    fail_before_execute: bool,
) -> Result<(), StoreError> {
    let current = read_relation_rows(table).await?;
    if current == rows {
        return Ok(());
    }
    let reader = Box::new(RecordBatchIterator::new(
        vec![Ok(relations_batch(rows)?)],
        crate::relations::relations_schema(),
    ));
    let mut merge = table.merge_insert(&["row_id"]);
    merge
        .when_matched_update_all(None)
        .when_not_matched_insert_all()
        .when_not_matched_by_source_delete(None);
    if fail_before_execute {
        return Err(StoreError::Projection);
    }
    merge
        .execute(reader)
        .await
        .map_err(|_| StoreError::Projection)?;
    Ok(())
}
async fn commit_search_rows(
    table: &Table,
    rows: &[SearchProjectionRow],
    fail_before_execute: bool,
) -> Result<(), StoreError> {
    let current = read_search_rows(table).await?;
    if current == rows {
        return Ok(());
    }
    let reader = Box::new(RecordBatchIterator::new(
        vec![Ok(search_batch(rows)?)],
        crate::search::search_schema(),
    ));
    let mut merge = table.merge_insert(&["row_id"]);
    merge
        .when_matched_update_all(None)
        .when_not_matched_insert_all()
        .when_not_matched_by_source_delete(None);
    if fail_before_execute {
        return Err(StoreError::Projection);
    }
    merge
        .execute(reader)
        .await
        .map_err(|_| StoreError::Projection)?;
    Ok(())
}
fn checkpoint_relation(rows: &[RelationProjectionRow]) -> Result<u64, StoreError> {
    rows.iter()
        .find(|row| row.row_id == crate::relations::RELATIONS_CHECKPOINT_ID)
        .map(|row| row.source_event_seq)
        .ok_or(StoreError::StoreCorrupt)
}
fn checkpoint_search(rows: &[SearchProjectionRow]) -> Result<u64, StoreError> {
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
