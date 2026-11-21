//! Request-local read admission facts shared by native presentations, never a search cache.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use evertrace_domain::{
    error::ErrorCode,
    query::{
        ExactFieldsQuery, ExactReadQuery, ExactRecordQuery, ExactRecordRef, MetadataReadOutcome,
    },
};
use evertrace_store::{JournalPayload, ObjectRow, projections::StoredFieldsContext};

use crate::{WriterHandle, repository::RepositoryReadAuthority};

/// Exact source inputs for one named current Work path. The rest of the lane is not an authorization operand.
pub(crate) struct LiveEpisodeRead {
    pub workstream_row: String,
    episode_revision: String,
    attempt_revision: String,
    pub sources: Option<BTreeSet<String>>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelationArchiveBudget {
    encoded: u64,
    decoded: u64,
}

impl Default for RelationArchiveBudget {
    fn default() -> Self {
        use evertrace_capture::cas::{
            PROTECTED_CONTENT_MAX_DECODED_BYTES, PROTECTED_CONTENT_MAX_ENCODED_BYTES,
        };
        Self {
            encoded: PROTECTED_CONTENT_MAX_ENCODED_BYTES,
            decoded: PROTECTED_CONTENT_MAX_DECODED_BYTES,
        }
    }
}

impl LiveEpisodeRead {
    pub(crate) fn contains(&self, row: &ObjectRow) -> bool {
        match row.object_kind.as_deref() {
            Some("work_episode") => {
                row.current_revision_id.as_ref() == Some(&self.episode_revision)
            }
            Some("attempt") => row.current_revision_id.as_ref() == Some(&self.attempt_revision),
            _ => false,
        }
    }

    pub(crate) fn admitted(&self, revisions: &BTreeSet<String>) -> bool {
        revisions.contains(&self.episode_revision) || revisions.contains(&self.attempt_revision)
    }

    pub(crate) fn withhold(&self, revisions: &mut BTreeSet<String>) {
        revisions.remove(&self.episode_revision);
        revisions.remove(&self.attempt_revision);
    }

    pub(crate) async fn check_archive(
        &self,
        writer: &WriterHandle,
        cas_dir: &std::path::Path,
        index: &BTreeMap<&str, Vec<&ObjectRow>>,
        budget: &mut RelationArchiveBudget,
        deadline: Instant,
    ) -> bool {
        let Some(sources) = &self.sources else {
            return false;
        };
        check_relation_archive(sources, writer, cas_dir, index, budget, deadline).await
    }
}

/// Run only after source, repository and deletion authorization. Do not return or retain source bytes.
pub(crate) async fn check_relation_archive(
    sources: &BTreeSet<String>,
    writer: &WriterHandle,
    cas_dir: &std::path::Path,
    index: &BTreeMap<&str, Vec<&ObjectRow>>,
    budget: &mut RelationArchiveBudget,
    deadline: Instant,
) -> bool {
    use evertrace_capture::{CasError, CasStore, cas::SourceArchiveVerifier};
    use evertrace_domain::ids::SourceObservationId;
    let archives = || {
        sources
            .iter()
            .filter(|reference| reference.parse::<SourceObservationId>().is_ok())
            .map(|reference| {
                source_archive(reference, |key| match index.get(key)?.as_slice() {
                    [row] => Some(*row),
                    _ => None,
                })
            })
            .take(usize::from(evertrace_domain::query::METADATA_READ_LIMIT) + 1)
            .collect::<Option<Vec<_>>>()
    };
    let Some(archives) = archives() else {
        return false;
    };
    if archives.is_empty()
        || archives.len() > usize::from(evertrace_domain::query::METADATA_READ_LIMIT)
    {
        return false;
    }
    let cas_dir = cas_dir.to_path_buf();
    let mut remaining = *budget;
    let read = writer
        .read_handle()
        .read_blocking(move |cancel| {
            let mut check = || {
                cancel.check().map_err(|_| CasError::ReadCancelled)?;
                if Instant::now() >= deadline {
                    return Err(CasError::ReadCancelled);
                }
                Ok(())
            };
            let verify = || -> Result<RelationArchiveBudget, CasError> {
                let cas = CasStore::open_existing(cas_dir)?;
                for (receipt, observation) in archives {
                    check()?;
                    let digest = receipt.cas_ref.parse()?;
                    let mut source = SourceArchiveVerifier::new(&receipt, &observation)?;
                    let window = cas.read_bounded_window_checked(
                        &digest,
                        remaining.encoded,
                        remaining.decoded,
                        0..0,
                        &mut check,
                        &mut |chunk| source.update(chunk),
                    )?;
                    source.finish()?;
                    remaining.encoded -= window.encoded_bytes;
                    remaining.decoded -= window.total_bytes;
                }
                check()?;
                Ok(remaining)
            };
            Ok(verify().ok())
        })
        .await;
    if let Ok(Some(remaining)) = read {
        *budget = remaining;
        true
    } else {
        // A failed verification may have consumed the read budget. Do not retry it within this stream.
        *budget = RelationArchiveBudget {
            encoded: 0,
            decoded: 0,
        };
        false
    }
}

impl LiveEpisodeRead {
    pub(crate) fn for_relation(
        snapshot: &evertrace_store::ProjectionSnapshot,
        index: &BTreeMap<&str, Vec<&ObjectRow>>,
        facets: &evertrace_domain::query::QueryFacetSet,
        selection: evertrace_domain::query::MemoryScopeSelection,
        deadline: Instant,
    ) -> Option<Self> {
        use evertrace_domain::{
            evidence::PairingState,
            ids::{SourceObservationId, WorkstreamId},
            query::{MemoryScopeSelection as Scope, TemporalMode},
            work::*,
        };
        if facets.temporal_mode != TemporalMode::Current
            || !facets.temporal_qualifiers.is_empty()
            || !facets.relation_requirements.iter().any(|kind| {
                matches!(
                    kind.as_str(),
                    "episode_to_workstream" | "episode_to_attempt"
                )
            })
        {
            return None;
        }
        let [anchor] = facets.target_anchors.as_slice() else {
            return None;
        };
        let stream_id = anchor.parse::<WorkstreamId>().ok()?;
        let current = |reference: &str, kind: &str| {
            let candidates = index.get(reference)?;
            if candidates.len() > usize::from(evertrace_domain::query::METADATA_READ_LIMIT) {
                return None;
            }
            let head = candidates
                .iter()
                .copied()
                .filter(|row| {
                    row.row_class == Some(evertrace_store::ObjectRowClass::Object)
                        && row.object_kind.as_deref() == Some(kind)
                        && row.object_id.as_deref() == Some(reference)
                })
                .max_by_key(|row| row.source_event_seq)?;
            let payload: JournalPayload =
                serde_json::from_str(head.payload_json.as_deref()?).ok()?;
            payload.validate().ok()?;
            Some((head, payload))
        };
        let (stream_row, JournalPayload::WorkstreamRecorded(work)) = current(anchor, "workstream")?
        else {
            return None;
        };
        let repository = work.repository_instance_id?;
        let tree = work.active_worktree_instance_id?;
        let in_scope = match selection {
            Scope::All => true,
            Scope::Task { task_id } => task_id == work.task_id,
            Scope::Repository { repository_id } => repository_id == repository,
            Scope::Worktree { worktree_id } => worktree_id == tree,
            Scope::Global | Scope::Unassigned => false,
        };
        if !in_scope {
            return None;
        }
        let episode_id = work.active_episode_id?;
        let (episode_row, JournalPayload::WorkEpisodeRecorded(episode)) =
            current(&episode_id.to_string(), "work_episode")?
        else {
            return None;
        };
        let [attempt_id] = episode.attempt_ids.as_slice() else {
            return None;
        };
        let (attempt_row, JournalPayload::AttemptRecorded(attempt)) =
            current(&attempt_id.to_string(), "attempt")?
        else {
            return None;
        };
        // This path supports an open plan, not completed work, a verifier, a recovered lane or a whole lane read.
        if work.workstream_id != stream_id
            || episode.episode_id != episode_id
            || attempt.attempt_id != *attempt_id
            || episode.workstream_id != stream_id
            || attempt.workstream_id != stream_id
            || episode.task_id != work.task_id
            || attempt.task_id != work.task_id
            || attempt.episode_id != Some(episode_id)
            || episode.repository_instance_id != Some(repository)
            || attempt.repository_instance_id != Some(repository)
            || episode.worktree_instance_id != Some(tree)
            || attempt.worktree_instance_ids.as_slice() != [tree]
            || episode.lifecycle_status != EpisodeLifecycle::Open
            || episode.boundary_candidate.is_some()
            || episode.capture_receipt_revision_ids.is_empty()
            || episode.execution_lane_ids.is_empty()
            || !episode.operation_burst_refs.is_empty()
            || !episode.open_loops.is_empty()
            || !episode.checkpoint_refs.is_empty()
            || !episode.competing_attempt_group_ids.is_empty()
            || !episode.worktree_transition_refs.is_empty()
            || !episode.interruption_refs.is_empty()
            || !episode.completed_outcome_refs.is_empty()
            || !episode.selected_outcome_refs.is_empty()
            || !episode.verification_refs.is_empty()
            || !episode.segmentation_correction_refs.is_empty()
            || !episode.capture_gap_refs.is_empty()
            || !episode.capture_outage_refs.is_empty()
            || !episode.semantic_digest_refs.is_empty()
            || !episode.failure_refs.is_empty()
            || !episode.work_artifact_refs.is_empty()
            || !episode.experiment_run_refs.is_empty()
            || attempt.lifecycle_status != AttemptLifecycleStatus::Active
            || attempt.execution_status != AttemptExecutionStatus::Proposed
            || attempt.outcome_state != AttemptOutcomeState::Unknown
            || !attempt.experiment_run_ids.is_empty()
            || attempt.verification != AttemptVerification::Unverified
            || attempt.adoption_status != AttemptAdoptionStatus::None
            || !attempt.execution_lane_ids.is_empty()
            || !attempt.work_binding_revision_refs.is_empty()
            || attempt.resume_state_assessment.is_some()
            || !attempt.composed_from_attempt_ids.is_empty()
            || !attempt.competing_group_ids.is_empty()
            || !attempt.worktree_transition_refs.is_empty()
            || !attempt.local_outcome_refs.is_empty()
            || attempt.strategy_contract.search_policy_ref.is_some()
            || attempt.strategy_contract.objective_ref.is_some()
        {
            return None;
        }
        let task_key = work.task_id.to_string();
        let mut bindings = BTreeMap::new();
        let count_limit = usize::from(evertrace_domain::query::METADATA_READ_LIMIT);
        let mut budget = count_limit;
        let mut bytes = evertrace_store::projections::READ_DEPENDENCY_BYTES;
        for row in snapshot.data_rows() {
            if Instant::now() >= deadline {
                return None;
            }
            if row.object_kind.as_deref() != Some("work_binding")
                || row.workstream_id.as_deref() != Some(anchor.as_str())
            {
                continue;
            }
            budget = budget.checked_sub(1)?;
            let payload = row.payload_json.as_deref()?;
            bytes = bytes.checked_sub(payload.len() as u64)?;
            let JournalPayload::WorkBindingRecorded(binding) =
                serde_json::from_str(payload).ok()?
            else {
                return None;
            };
            // Store admission locks an assigned Episode across successors and verifies its reciprocal scope.
            if binding.primary_binding.episode_id != Some(episode_id) {
                continue;
            }
            binding.validate().ok()?;
            if row.task_id.as_deref() != Some(task_key.as_str())
                || binding.primary_binding.workstream_id != Some(stream_id)
                || binding.primary_binding.task_id != Some(work.task_id)
            {
                return None;
            }
            match bindings.entry(binding.operation_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(binding);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry.get().revision_generation == binding.revision_generation {
                        return None;
                    }
                    if entry.get().revision_generation < binding.revision_generation {
                        entry.insert(binding);
                    }
                }
            }
        }
        if bindings.is_empty() || work.worktree_lineage_refs.is_empty() {
            return None;
        }
        let sources = (|| {
            let mut evidence = BTreeSet::new();
            let entry = episode.entry_worktree_snapshot_id?;
            let (_, JournalPayload::WorktreeSnapshotRecorded(pinned)) =
                current(&entry.to_string(), "worktree_snapshot")?
            else {
                return None;
            };
            if pinned.worktree_snapshot_id != entry || pinned.worktree_instance_id != tree {
                return None;
            }
            let mut sources = BTreeSet::from([entry.to_string()]);
            let source_is_present = |reference: &str| {
                matches!(current(reference, "source_observation"), Some((_, JournalPayload::SourceObservationRecorded(value)))
                if reference.parse::<SourceObservationId>().ok() == Some(value.source_observation_id))
            };
            for binding in bindings.into_values() {
                if binding.assignment_status != AssignmentStatus::Resolved
                    || binding.scope_effect_refs.is_empty()
                    || !binding.secondary_bindings.is_empty()
                    || binding
                        .primary_binding
                        .attempt_id
                        .is_some_and(|id| id != *attempt_id)
                    || binding.primary_binding.experiment_run_id.is_some()
                    || binding.primary_binding.competing_group_id.is_some()
                {
                    return None;
                }
                let (_, JournalPayload::OperationDerived(operation)) =
                    current(&binding.operation_id.to_string(), "operation")?
                else {
                    return None;
                };
                if operation.operation_id != binding.operation_id
                    || operation.pairing_state == PairingState::Conflicted
                    || !operation
                        .execution_lane_id
                        .is_some_and(|lane| episode.execution_lane_ids.contains(&lane))
                {
                    return None;
                }
                for observation in operation
                    .input_source_observation_refs
                    .iter()
                    .chain(&operation.result_source_observation_refs)
                {
                    let reference = observation.to_string();
                    if !source_is_present(&reference) {
                        return None;
                    }
                    sources.insert(reference);
                }
                for id in &binding.scope_effect_refs {
                    let reference = id.to_string();
                    let (_, JournalPayload::ScopeEffectDerived(effect)) =
                        current(&reference, "scope_effect")?
                    else {
                        return None;
                    };
                    if effect.scope_effect_id != *id
                        || !operation.scope_effect_ids.contains(id)
                        || effect.operation_id != binding.operation_id
                        || effect.repository_instance_id != Some(repository)
                        || effect.worktree_instance_id != Some(tree)
                    {
                        return None;
                    }
                    sources.insert(reference);
                    for observation in effect.evidence_refs {
                        let reference = observation.to_string();
                        if !source_is_present(&reference) {
                            return None;
                        }
                        sources.insert(reference);
                    }
                }
                for reference in binding.evidence_refs {
                    if !source_is_present(&reference) {
                        return None;
                    }
                    evidence.insert(reference);
                }
                if evidence.len() + sources.len() > count_limit {
                    return None;
                }
            }
            if !work
                .worktree_lineage_refs
                .iter()
                .all(|reference| evidence.contains(reference))
            {
                return None;
            }
            sources.extend(evidence);
            Some(sources)
        })();
        Some(Self {
            workstream_row: stream_row.row_id.clone(),
            episode_revision: episode_row.current_revision_id.clone()?,
            attempt_revision: attempt_row.current_revision_id.clone()?,
            sources,
        })
    }
}

/// Only admit the current assignment of the named Operation, not the newest one mentioning a given effect.
pub(crate) async fn current_operation_binding<'a>(
    search: &evertrace_store::SearchIndex,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
    facets: &evertrace_domain::query::QueryFacetSet,
    frontier: u64,
    deadline: Instant,
) -> Option<&'a ObjectRow> {
    use evertrace_domain::{ids::OperationId, query::TemporalMode};
    if facets.temporal_mode != TemporalMode::Current
        || !facets.temporal_qualifiers.is_empty()
        || !facets
            .relation_requirements
            .iter()
            .any(|kind| kind == "binding_to_scope_effect")
    {
        return None;
    }
    let [operation] = facets.target_anchors.as_slice() else {
        return None;
    };
    let operation_id = operation.parse::<OperationId>().ok()?;
    let refs = operation_binding_references(search, operation, frontier).await?;
    select_operation_binding(operation_id, &refs, index, frontier, deadline)
}

pub(crate) async fn operation_binding_references(
    search: &evertrace_store::SearchIndex,
    operation: &str,
    frontier: u64,
) -> Option<Vec<String>> {
    let neighbours = {
        let snapshot = search
            .snapshot_after_validated_frontier(frontier)
            .await
            .ok()?;
        if snapshot.frontier() != frontier || snapshot.authoritative_frontier() != frontier {
            return None;
        }
        snapshot
            .adjacent_relations(
                &[operation.to_owned()],
                &["operation_to_binding_revision".into()],
                65,
            )
            .await
            .ok()??
    };
    if neighbours.len() > 64 {
        return None;
    }
    neighbours
        .into_iter()
        .map(|edge| {
            (edge.source_id.as_deref() == Some(operation))
                .then_some(edge.target_id)
                .flatten()
        })
        .collect()
}

pub(crate) fn select_operation_binding<'a>(
    operation_id: evertrace_domain::ids::OperationId,
    references: &[String],
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
    frontier: u64,
    deadline: Instant,
) -> Option<&'a ObjectRow> {
    use evertrace_domain::work::AssignmentStatus;
    let mut rows = Vec::new();
    let mut bytes = evertrace_store::projections::READ_DEPENDENCY_BYTES;
    for reference in references {
        if Instant::now() >= deadline {
            return None;
        }
        let [row] = index.get(reference.as_str())?.as_slice() else {
            return None;
        };
        if row.object_kind.as_deref() != Some("work_binding")
            || row.object_id.as_ref() != Some(reference)
        {
            return None;
        }
        bytes = bytes.checked_sub(row.payload_json.as_ref()?.len() as u64)?;
        rows.push((*row).clone());
    }
    let view = evertrace_store::WorkBindingCurrentView::from_rows(frontier, &rows).ok()?;
    if view.bindings.len() != 1 {
        return None;
    }
    let binding = view.bindings.get(&operation_id)?;
    if binding.assignment_status != AssignmentStatus::Resolved {
        return None;
    }
    let [row] = index
        .get(binding.work_binding_revision_id.to_string().as_str())?
        .as_slice()
    else {
        return None;
    };
    Some(*row)
}

pub(crate) fn physical_read_index(rows: &[ObjectRow]) -> BTreeMap<&str, Vec<&ObjectRow>> {
    let mut index = BTreeMap::<&str, Vec<&ObjectRow>>::new();
    for row in rows {
        for key in [
            Some(row.row_id.as_str()),
            row.object_id.as_deref(),
            row.current_revision_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let entries = index.entry(key).or_default();
            if entries.last().is_none_or(|last| last.row_id != row.row_id) {
                entries.push(row);
            }
        }
    }
    index
}

pub(crate) struct OperationBindingRead<'a> {
    operation: &'a ObjectRow,
    effects: Vec<(&'a ObjectRow, evertrace_domain::evidence::ScopeEffect)>,
    covers_operation: bool,
    pub sources: BTreeSet<String>,
}

impl OperationBindingRead<'_> {
    /// Exact-only operands for a single physical shard. Indexed rows and durable coordinates stay unchanged.
    pub(crate) fn scoped_operands(
        &self,
        selection: evertrace_domain::query::MemoryScopeSelection,
        binding: &mut evertrace_store::SearchProjectionRow,
    ) -> Option<Vec<evertrace_store::SearchProjectionRow>> {
        use evertrace_domain::query::MemoryScopeSelection as Scope;
        if selection == Scope::All {
            return Some(Vec::new());
        }
        if !self.covers_operation {
            return None;
        }
        let (_, first) = self.effects.first()?;
        let (repo, tree) = (first.repository_instance_id, first.worktree_instance_id);
        if self.effects.iter().any(|(_, effect)| {
            effect.repository_instance_id != repo || effect.worktree_instance_id != tree
        }) {
            return None;
        }
        match selection {
            Scope::Repository { repository_id } if repo == Some(repository_id) => {}
            Scope::Worktree { worktree_id } if repo.is_some() && tree == Some(worktree_id) => {}
            Scope::Task { task_id }
                if binding.task_id.as_deref() == Some(task_id.to_string().as_str()) => {}
            _ => return None,
        }
        binding.repository_id = repo.map(|id| id.to_string());
        binding.worktree_id = tree.map(|id| id.to_string());
        let mut rows = Vec::new();
        for row in std::iter::once(self.operation).chain(self.effects.iter().map(|(row, _)| *row)) {
            let mut source = evertrace_store::query::canonical_physical_source(row).ok()?;
            source.task_id.clone_from(&binding.task_id);
            source.repository_id.clone_from(&binding.repository_id);
            source.worktree_id.clone_from(&binding.worktree_id);
            rows.push(source);
        }
        Some(rows)
    }
}

pub(crate) fn operation_binding_read<'a>(
    row: &ObjectRow,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
) -> Option<OperationBindingRead<'a>> {
    use evertrace_domain::{
        evidence::PairingState, ids::SourceObservationId, work::AssignmentStatus,
    };
    let JournalPayload::WorkBindingRecorded(binding) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if binding.assignment_status != AssignmentStatus::Resolved
        || binding.scope_effect_refs.is_empty()
    {
        return None;
    }
    let operation_ref = binding.operation_id.to_string();
    let operation_row = *index
        .get(operation_ref.as_str())?
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("operation"))
        .max_by_key(|row| row.source_event_seq)?;
    let JournalPayload::OperationDerived(operation) =
        serde_json::from_str(operation_row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if operation.operation_id != binding.operation_id
        || operation.pairing_state != PairingState::Paired
    {
        return None;
    }
    let mut sources: BTreeSet<_> = binding.evidence_refs.iter().cloned().collect();
    sources.extend(
        operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .map(ToString::to_string),
    );
    let mut effects = Vec::new();
    for id in &binding.scope_effect_refs {
        let reference = id.to_string();
        let [row] = index.get(reference.as_str())?.as_slice() else {
            return None;
        };
        let JournalPayload::ScopeEffectDerived(effect) =
            serde_json::from_str(row.payload_json.as_deref()?).ok()?
        else {
            return None;
        };
        if effect.scope_effect_id != *id
            || effect.operation_id != operation.operation_id
            || !operation.scope_effect_ids.contains(id)
        {
            return None;
        }
        sources.extend(effect.evidence_refs.iter().map(ToString::to_string));
        effects.push((*row, *effect));
    }
    (row.task_id.as_deref()
        == binding
            .primary_binding
            .task_id
            .map(|id| id.to_string())
            .as_deref()
        && sources
            .iter()
            .all(|reference| reference.parse::<SourceObservationId>().is_ok()))
    .then_some(OperationBindingRead {
        operation: operation_row,
        effects,
        covers_operation: operation.scope_effect_ids.len() == binding.scope_effect_refs.len(),
        sources,
    })
}

/// Assess only the canonical source and repository closure; observation recording belongs to callers.
pub(crate) async fn check_source_access(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    all_rows: &[ObjectRow],
    rows: &[&ObjectRow],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    for chunk in rows.chunks(usize::from(evertrace_domain::query::METADATA_READ_LIMIT)) {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted);
        }
        if !crate::session_import::source_rows_read_assessment(
            writer,
            authority,
            all_rows,
            chunk,
            None,
            Some(deadline),
        )
        .await
        .map_err(|_| ErrorCode::StoreCorrupt)?
        .0
        .is_empty()
        {
            return Err(ErrorCode::Untrusted);
        }
    }
    let scopes = crate::repository::row_repository_contexts_from_scopes(all_rows.iter(), rows)
        .map_err(|_| ErrorCode::StoreCorrupt)?;
    if !crate::repository::repository_read_assessment(
        writer,
        scopes.values().flatten().copied().collect(),
        authority,
        deadline,
    )
    .await
    .map_err(|_| ErrorCode::StoreCorrupt)?
    .0
    .is_empty()
    {
        return Err(ErrorCode::Untrusted);
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::ResourceExhausted);
    }
    Ok(())
}

pub(crate) fn source_receipt<'a>(
    reference: &str,
    find_row: impl Fn(&str) -> Option<&'a ObjectRow>,
) -> Option<Box<evertrace_domain::evidence::SourceReceipt>> {
    source_archive(reference, find_row).map(|(receipt, _)| receipt)
}

type SourceArchive = (
    Box<evertrace_domain::evidence::SourceReceipt>,
    Box<evertrace_domain::evidence::SourceObservation>,
);

fn source_archive<'a>(
    reference: &str,
    find_row: impl Fn(&str) -> Option<&'a ObjectRow>,
) -> Option<SourceArchive> {
    // Resolve stable public source/span identities, not an indexed timestamp.
    let observation_id = reference
        .parse::<evertrace_domain::ids::SourceObservationId>()
        .ok()
        .or_else(|| {
            evertrace_domain::evidence::EvidenceSurface::parse_candidate_ref(reference)
                .map(|value| value.0)
        })?;
    let reference = observation_id.to_string();
    let key = format!("object:evidence:source_observation:{reference}");
    let row = find_row(&key)?;
    let JournalPayload::SourceObservationRecorded(observation) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    let key = format!(
        "object:evidence:source_receipt:{}",
        observation.source_receipt_ref
    );
    let row = find_row(&key)?;
    let JournalPayload::SourceReceiptRecorded(receipt) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if receipt.source_observation_id.to_string() != reference
        || receipt.source_receipt_id != observation.source_receipt_ref
        || receipt.source_instance_id != observation.source_instance_id
        || receipt.source_revision != observation.source_revision
        || receipt.validate().is_err()
    {
        return None;
    }
    Some((receipt, observation))
}

/// Use the existing bounded exact-read dependencies for scoped search candidates.
/// A bare index scope is not proof that the source of its text remains readable.
pub(crate) struct SearchReadAccess<'a> {
    pub writer: &'a WriterHandle,
    pub authority: RepositoryReadAuthority<'a>,
    pub frontier: u64,
    pub config_hash: [u8; 32],
    pub deadline: Instant,
}

/// Ordinary Search families whose public current revision and source/scope closure use exact reads.
pub(crate) const SCOPED_OBJECT_KINDS: &[&str] = &[
    "atom_revision",
    "task",
    "workstream",
    "work_episode",
    "attempt",
    "procedure_revision",
    "revision_proposal_revision",
    "semantic_digest",
];

impl SearchReadAccess<'_> {
    pub async fn check_revision(&self, revision: &str) -> Result<(), ErrorCode> {
        self.check(
            ExactReadQuery::Fields(ExactFieldsQuery {
                revision_ref: revision.to_owned(),
            }),
            revision,
            "atom_revision",
        )
        .await
        .map(drop)
    }

    /// A lagging index may offer an immutable revision; only its current alias can grant Search access.
    pub(crate) async fn check_current(
        &self,
        key: &str,
        revision: &str,
        kind: &str,
    ) -> Result<(), ErrorCode> {
        let context = self.check_record(key, revision, kind).await?;
        let row = context.selected.as_ref().ok_or(ErrorCode::StoreCorrupt)?;
        if row.object_id.as_deref() != Some(key) {
            return Err(ErrorCode::StoreCorrupt);
        }
        if matches!(
            kind,
            "procedure_revision" | "revision_proposal_revision" | "semantic_digest"
        ) {
            // A missing or suppressed dependency is not permission to use compiled text.
            let present = |reference: &str| {
                context.rows.iter().any(|fact| {
                    fact.object_id.as_deref() == Some(reference)
                        || fact.current_revision_id.as_deref() == Some(reference)
                })
            };
            let payload =
                serde_json::from_str(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
                    .map_err(|_| ErrorCode::StoreCorrupt)?;
            let draft = match &payload {
                JournalPayload::ProcedureRevisionRecorded(procedure) => &procedure.draft,
                JournalPayload::RevisionProposalRecorded(proposal) => {
                    let evertrace_domain::semantic::ProposalPayload::Procedure(method) =
                        &proposal.payload
                    else {
                        return Err(ErrorCode::Untrusted);
                    };
                    if !proposal
                        .source_cohort_refs
                        .iter()
                        .chain(&proposal.evidence_refs)
                        .all(|id| present(id))
                    {
                        return Err(ErrorCode::Untrusted);
                    }
                    method.draft()
                }
                JournalPayload::SemanticDigestRecorded(digest) => {
                    return if digest.selected_direct_refs.iter().all(|id| present(id))
                        && digest
                            .episode_revision_id
                            .is_none_or(|id| present(&id.to_string()))
                    {
                        Ok(())
                    } else {
                        Err(ErrorCode::Untrusted)
                    };
                }
                _ => return Err(ErrorCode::StoreCorrupt),
            };
            if draft.evidence_refs.iter().any(|id| !present(id))
                || draft
                    .support_revision_refs
                    .iter()
                    .any(|id| !present(&id.to_string()))
            {
                return Err(ErrorCode::Untrusted);
            }
        }
        if kind == "work_episode" {
            let JournalPayload::WorkEpisodeRecorded(episode) =
                serde_json::from_str(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
                    .map_err(|_| ErrorCode::StoreCorrupt)?
            else {
                return Err(ErrorCode::StoreCorrupt);
            };
            if episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Closed {
                return Ok(());
            }
            let read_payload = |kind: &str, reference: &str| {
                context
                    .rows
                    .iter()
                    .find(|row| {
                        row.object_kind.as_deref() == Some(kind)
                            && row.object_id.as_deref() == Some(reference)
                    })
                    .and_then(|row| row.payload_json.as_deref())
                    .ok_or(ErrorCode::Untrusted)
            };
            if let Some(snapshot) = episode
                .exit_worktree_snapshot_id
                .or(episode.entry_worktree_snapshot_id)
            {
                let payload = read_payload("worktree_snapshot", &snapshot.to_string())?;
                if !matches!(serde_json::from_str::<JournalPayload>(payload),
                    Ok(JournalPayload::WorktreeSnapshotRecorded(snapshot))
                        if Some(snapshot.worktree_instance_id) == episode.worktree_instance_id)
                {
                    return Err(ErrorCode::Untrusted);
                }
            } else if let Some(worktree) = episode.worktree_instance_id {
                let payload = read_payload("worktree", &worktree.to_string())?;
                if !matches!(serde_json::from_str::<JournalPayload>(payload),
                    Ok(JournalPayload::WorktreeInstanceRecorded(tree))
                        if tree.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active)
                {
                    return Err(ErrorCode::ResourceExhausted);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn check_evidence(&self, source: &str) -> Result<(), ErrorCode> {
        self.check_record(source, source, "source_observation")
            .await
            .map(drop)
    }

    pub(super) async fn checked_source_receipt(
        &self,
        source: &str,
    ) -> Result<Box<evertrace_domain::evidence::SourceReceipt>, ErrorCode> {
        let context = self
            .check_record(source, source, "source_observation")
            .await?;
        source_receipt(source, |key| {
            context.rows.iter().find(|row| row.row_id == key)
        })
        .ok_or(ErrorCode::StoreCorrupt)
    }

    pub(crate) async fn check_record(
        &self,
        key: &str,
        revision: &str,
        kind: &str,
    ) -> Result<Box<StoredFieldsContext>, ErrorCode> {
        let query = ExactReadQuery::Record(ExactRecordQuery {
            reference: ExactRecordRef {
                stable_key: key.to_owned(),
                revision_ref: None,
            },
            field: None,
            range: None,
            expected_data_identity: None,
            expected_selection: None,
        });
        self.check(query, revision, kind).await
    }

    async fn check(
        &self,
        query: ExactReadQuery,
        revision: &str,
        kind: &str,
    ) -> Result<Box<StoredFieldsContext>, ErrorCode> {
        let read = async {
            let (cancelled, _cancel_on_drop) =
                evertrace_store::StoreReadHandle::cancellation_scope();
            let MetadataReadOutcome::Page(context) = self
                .writer
                .read_stored_fields_context(
                    Box::new(query),
                    cancelled,
                    self.deadline,
                    self.config_hash,
                )
                .await
                .map_err(|_| ErrorCode::StoreCorrupt)?
            else {
                return Err(ErrorCode::ResourceExhausted);
            };
            if context.state.frontier != self.frontier
                || context.selected.as_ref().is_none_or(|row| {
                    row.current_revision_id.as_deref() != Some(revision)
                        || row.object_kind.as_deref() != Some(kind)
                })
            {
                return Err(ErrorCode::StoreCorrupt);
            }
            if context.source_suppressed {
                return Err(ErrorCode::Untrusted);
            }
            let refs = context.rows.iter().collect::<Vec<_>>();
            check_source_access(
                self.writer,
                &self.authority,
                &context.rows,
                &refs,
                self.deadline,
            )
            .await?;
            let state = self
                .writer
                .read_handle()
                .state()
                .await
                .map_err(|_| ErrorCode::StoreCorrupt)?;
            if state != (self.frontier, context.state.data_identity) {
                return Err(ErrorCode::StoreCorrupt);
            }
            Ok(context)
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(self.deadline), read)
            .await
            .map_err(|_| ErrorCode::ResourceExhausted)?
    }
}
