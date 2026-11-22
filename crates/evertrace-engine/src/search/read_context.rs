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
    use evertrace_capture::cas::SourceArchiveVerifier;
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
    read_relation_archive(
        writer,
        cas_dir,
        budget,
        deadline,
        move |cas, remaining, check| {
            for (receipt, observation) in archives {
                let digest = receipt.cas_ref.parse()?;
                let mut source = SourceArchiveVerifier::new(&receipt, &observation)?;
                remaining.verify(cas, &digest, check, &mut |chunk| source.update(chunk))?;
                source.finish()?;
            }
            Ok(())
        },
    )
    .await
}

type ArchiveCheck<'a> = dyn FnMut() -> Result<(), evertrace_capture::CasError> + 'a;

impl RelationArchiveBudget {
    fn verify(
        &mut self,
        cas: &evertrace_capture::CasStore,
        digest: &evertrace_capture::CasDigest,
        check: &mut ArchiveCheck<'_>,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), evertrace_capture::CasError>,
    ) -> Result<(), evertrace_capture::CasError> {
        check()?;
        let window = cas.read_bounded_window_checked(
            digest,
            self.encoded,
            self.decoded,
            0..0,
            check,
            visitor,
        )?;
        self.encoded -= window.encoded_bytes;
        self.decoded -= window.total_bytes;
        Ok(())
    }
}

async fn read_relation_archive(
    writer: &WriterHandle,
    cas_dir: &std::path::Path,
    budget: &mut RelationArchiveBudget,
    deadline: Instant,
    verify: impl FnOnce(
        &evertrace_capture::CasStore,
        &mut RelationArchiveBudget,
        &mut ArchiveCheck<'_>,
    ) -> Result<(), evertrace_capture::CasError>
    + Send
    + 'static,
) -> bool {
    use evertrace_capture::{CasError, CasStore};
    let cas_dir = cas_dir.to_path_buf();
    let mut remaining = *budget;
    let read = writer
        .read_handle()
        .read_blocking(move |cancel| {
            let mut check = || {
                cancel.check().map_err(|_| CasError::ReadCancelled)?;
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(CasError::ReadCancelled)
                }
            };
            let result = CasStore::open_existing(cas_dir).and_then(|cas| {
                verify(&cas, &mut remaining, &mut check)?;
                check()
            });
            Ok((result, remaining))
        })
        .await;
    match read {
        Ok((Ok(()), remaining)) => {
            *budget = remaining;
            true
        }
        Ok((Err(CasError::NotFound), remaining)) => {
            // The missing file was detected before any bytes of it were read.
            *budget = remaining;
            false
        }
        _ => {
            // A failed verification may have consumed unreported bytes.
            *budget = RelationArchiveBudget {
                encoded: 0,
                decoded: 0,
            };
            false
        }
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

pub(crate) struct OperationRead<'a> {
    operation: &'a ObjectRow,
    effects: Vec<(&'a ObjectRow, evertrace_domain::evidence::ScopeEffect)>,
    covers_operation: bool,
    pub sources: BTreeSet<String>,
    pub physical_sources: BTreeSet<String>,
}

impl OperationRead<'_> {
    fn shard(
        &self,
    ) -> Option<(
        Option<evertrace_domain::ids::RepositoryId>,
        Option<evertrace_domain::ids::WorktreeId>,
    )> {
        let (_, first) = self.effects.first()?;
        let key = (first.repository_instance_id, first.worktree_instance_id);
        (self.covers_operation
            && self.effects.iter().all(|(_, effect)| {
                (effect.repository_instance_id, effect.worktree_instance_id) == key
            }))
        .then_some(key)
    }

    fn rows(&self) -> impl Iterator<Item = &ObjectRow> {
        std::iter::once(self.operation).chain(self.effects.iter().map(|(row, _)| *row))
    }

    pub(crate) fn contains(&self, reference: &str) -> bool {
        self.rows()
            .any(|row| row.current_revision_id.as_deref() == Some(reference))
    }

    pub(crate) fn repository_operands(&self) -> Option<Vec<evertrace_store::SearchProjectionRow>> {
        let (repository, worktree) = self.shard()?;
        self.operands(
            &None,
            &Some(repository?.to_string()),
            &worktree.map(|id| id.to_string()),
        )
    }

    fn operands(
        &self,
        task: &Option<String>,
        repository: &Option<String>,
        worktree: &Option<String>,
    ) -> Option<Vec<evertrace_store::SearchProjectionRow>> {
        self.rows()
            .map(|row| {
                let mut source = evertrace_store::query::canonical_physical_source(row).ok()?;
                source.task_id.clone_from(task);
                source.repository_id.clone_from(repository);
                source.worktree_id.clone_from(worktree);
                Some(source)
            })
            .collect()
    }

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
        let (repo, tree) = self.shard()?;
        match selection {
            Scope::Repository { repository_id } if repo == Some(repository_id) => {}
            Scope::Worktree { worktree_id } if repo.is_some() && tree == Some(worktree_id) => {}
            Scope::Task { task_id }
                if binding.task_id.as_deref() == Some(task_id.to_string().as_str()) => {}
            _ => return None,
        }
        binding.repository_id = repo.map(|id| id.to_string());
        binding.worktree_id = tree.map(|id| id.to_string());
        self.operands(
            &binding.task_id,
            &binding.repository_id,
            &binding.worktree_id,
        )
    }
}

pub(crate) fn operation_binding_read<'a>(
    row: &ObjectRow,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
) -> Option<OperationRead<'a>> {
    use evertrace_domain::{ids::SourceObservationId, work::AssignmentStatus};
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
    let mut read = operation_read(
        binding.operation_id,
        Some(&binding.scope_effect_refs),
        index,
    )?;
    read.sources.extend(binding.evidence_refs.iter().cloned());
    (row.task_id.as_deref()
        == binding
            .primary_binding
            .task_id
            .map(|id| id.to_string())
            .as_deref()
        && read
            .sources
            .iter()
            .all(|reference| reference.parse::<SourceObservationId>().is_ok()))
    .then_some(read)
}

/// Read an authorized physical prefix independently of WorkBinding. The persisted
/// relation channel covers the current physical revision only, even for exact pins.
pub(crate) fn repository_operation_read<'a>(
    selection: evertrace_domain::query::MemoryScopeSelection,
    facets: &evertrace_domain::query::QueryFacetSet,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
) -> Option<OperationRead<'a>> {
    use evertrace_domain::query::{
        MemoryScopeSelection as Scope, TemporalMode, parse_operation_revision,
    };
    if !matches!(selection, Scope::Repository { .. } | Scope::Worktree { .. })
        || !facets.temporal_qualifiers.is_empty()
        || !facets
            .relation_requirements
            .iter()
            .any(|kind| kind == "operation_to_scope_effect")
    {
        return None;
    }
    let [anchor] = facets.target_anchors.as_slice() else {
        return None;
    };
    let (id, exact) = match (facets.temporal_mode, parse_operation_revision(anchor)) {
        (TemporalMode::Current | TemporalMode::Any, Some((id, _))) => (id, true),
        (TemporalMode::Current, None) => (anchor.parse().ok()?, false),
        _ => return None,
    };
    let read = operation_read(id, None, index)?;
    if exact && read.operation.current_revision_id.as_ref() != Some(anchor) {
        return None;
    }
    let (Some(repo), tree) = read.shard()? else {
        return None;
    };
    match selection {
        Scope::Repository { repository_id } if repository_id == repo => Some(read),
        Scope::Worktree { worktree_id } if Some(worktree_id) == tree => Some(read),
        _ => None,
    }
}

fn operation_read<'a>(
    operation_id: evertrace_domain::ids::OperationId,
    selected: Option<&[evertrace_domain::ids::ScopeEffectId]>,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
) -> Option<OperationRead<'a>> {
    use evertrace_domain::evidence::PairingState;
    let key = operation_id.to_string();
    let operation_row = *index
        .get(key.as_str())?
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("operation"))
        .max_by_key(|row| row.source_event_seq)?;
    let JournalPayload::OperationDerived(operation) =
        serde_json::from_str(operation_row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if operation.operation_id != operation_id
        || operation.pairing_state != PairingState::Paired
        || operation.validate().is_err()
    {
        return None;
    }
    let selected = selected.unwrap_or(&operation.scope_effect_ids);
    if selected.is_empty()
        || selected.len() > usize::from(evertrace_domain::query::METADATA_READ_LIMIT)
    {
        return None;
    }
    let mut physical_sources: BTreeSet<_> = operation
        .input_source_observation_refs
        .iter()
        .chain(&operation.result_source_observation_refs)
        .map(ToString::to_string)
        .collect();
    let mut effects = Vec::new();
    for id in selected {
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
            || effect.validate().is_err()
            || effect.operation_id != operation.operation_id
            || !operation.scope_effect_ids.contains(id)
        {
            return None;
        }
        physical_sources.extend(effect.evidence_refs.iter().map(ToString::to_string));
        effects.push((*row, *effect));
    }
    Some(OperationRead {
        operation: operation_row,
        effects,
        covers_operation: operation.scope_effect_ids.len() == selected.len(),
        sources: physical_sources.clone(),
        physical_sources,
    })
}

pub(crate) const ATTEMPT_RUN_RELATION: &str = "run_to_attempt";
pub(crate) const RUN_RESULT_RELATION: &str = "result_produced_by_run";

pub(crate) async fn check_research_archive(
    row: &ObjectRow,
    writer: &WriterHandle,
    cas_dir: &std::path::Path,
    index: &BTreeMap<&str, Vec<&ObjectRow>>,
    budget: &mut RelationArchiveBudget,
    deadline: Instant,
) -> bool {
    let Some(payload) = row
        .payload_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
    else {
        return false;
    };
    match payload {
        JournalPayload::ExperimentRunRecorded(run) => {
            let observations = run
                .source_receipt_refs
                .iter()
                .chain(&run.terminal_evidence_refs)
                .map(|id| {
                    let key = format!("object:evidence:source_receipt:{id}");
                    let [row] = index.get(key.as_str())?.as_slice() else {
                        return None;
                    };
                    let JournalPayload::SourceReceiptRecorded(receipt) =
                        serde_json::from_str(row.payload_json.as_deref()?).ok()?
                    else {
                        return None;
                    };
                    (receipt.source_receipt_id == *id)
                        .then(|| receipt.source_observation_id.to_string())
                })
                .collect::<Option<BTreeSet<_>>>();
            let Some(observations) = observations else {
                return false;
            };
            check_relation_archive(&observations, writer, cas_dir, index, budget, deadline).await
        }
        JournalPayload::ResultEvidenceRecorded(result)
            if !result.raw_cas_refs.is_empty() && result.raw_cas_refs.len() <= 64 =>
        {
            read_relation_archive(
                writer,
                cas_dir,
                budget,
                deadline,
                move |cas, remaining, check| {
                    for id in &result.raw_cas_refs {
                        let id = id.to_string();
                        let digest = id[4..].parse()?;
                        remaining.verify(cas, &digest, check, &mut |_| Ok(()))?;
                    }
                    Ok(())
                },
            )
            .await
        }
        _ => false,
    }
}

pub(crate) const LINEAGE_RELATIONS: [&str; 2] = [
    evertrace_domain::query::TRANSITION_FROM_SNAPSHOT,
    evertrace_domain::query::TRANSITION_TO_SNAPSHOT,
];

pub(crate) struct LineageQuery {
    pub repository: evertrace_domain::ids::RepositoryId,
    pub revision: String,
    pub current: bool,
    pub requested: [bool; 2],
    pub verification: bool,
    pub current_only: bool,
}

#[derive(PartialEq)]
pub(crate) struct LineageRead {
    pub rows: Vec<evertrace_store::SearchProjectionRow>,
    pub edges: Vec<(String, String, String)>,
    pub verification_missing: bool,
}

impl LineageRead {
    pub(crate) fn covers(&self, reference: &str) -> bool {
        self.rows
            .iter()
            .any(|row| row.candidate_id.as_deref() == Some(reference))
    }
}

impl SearchReadAccess<'_> {
    /// Read only the nominated Transition and its immutable snapshot coordinates, not Worktree current pointers.
    pub(crate) async fn lineage(&self, query: &LineageQuery) -> Option<LineageRead> {
        use evertrace_domain::repository::{LineageAssessment, SnapshotCaptureStatus};
        let (id, version) = evertrace_domain::query::parse_transition_revision(&query.revision)?;
        let key = id.to_string();
        let context = self
            .check_exact_record(&key, &query.revision, "worktree_transition")
            .await
            .ok()?;
        let row = context.selected.as_ref()?;
        let JournalPayload::WorktreeTransitionRecorded(transition) =
            serde_json::from_str(row.payload_json.as_deref()?).ok()?
        else {
            return None;
        };
        if transition.worktree_transition_id != id || transition.transition_revision != version {
            return None;
        }
        let tree_in_repository = |tree: evertrace_domain::ids::WorktreeId| {
            let row = context
                .rows
                .iter()
                .find(|row| row.row_id == evertrace_store::repository::worktree_row_id(&tree))?;
            let JournalPayload::WorktreeInstanceRecorded(value) =
                serde_json::from_str(row.payload_json.as_deref()?).ok()?
            else {
                return None;
            };
            (value.worktree_instance_id == tree && value.repository_instance_id == query.repository)
                .then_some(())
        };
        tree_in_repository(transition.from_worktree_instance_id)?;
        tree_in_repository(transition.to_worktree_instance_id)?;
        let mut result = LineageRead {
            rows: vec![
                evertrace_store::query::canonical_lineage_source(
                    row,
                    query.repository,
                    query.current,
                )
                .ok()?,
            ],
            edges: Vec::new(),
            verification_missing: false,
        };
        if transition.lineage_assessment != LineageAssessment::Proven {
            return Some(result);
        }
        let endpoints = [
            (
                transition.from_worktree_instance_id,
                transition.from_snapshot_id,
            ),
            (
                transition.to_worktree_instance_id,
                transition.to_snapshot_id,
            ),
        ];
        for ((kind, requested), (tree, snapshot)) in LINEAGE_RELATIONS
            .into_iter()
            .zip(query.requested)
            .zip(endpoints)
        {
            let Some(snapshot) = snapshot.filter(|_| requested) else {
                continue;
            };
            let reference = snapshot.to_string();
            let Ok(endpoint) = self
                .check_record(&reference, &reference, "worktree_snapshot")
                .await
            else {
                continue;
            };
            let Some(row) = endpoint.selected.as_ref() else {
                continue;
            };
            let JournalPayload::WorktreeSnapshotRecorded(value) =
                serde_json::from_str(row.payload_json.as_deref()?).ok()?
            else {
                return None;
            };
            if value.worktree_instance_id != tree
                || value.worktree_snapshot_id != snapshot
                || value.capture_status != SnapshotCaptureStatus::Complete
            {
                continue;
            }
            if !result
                .rows
                .iter()
                .any(|row| row.candidate_id.as_ref() == Some(&reference))
            {
                result.rows.push(
                    evertrace_store::query::canonical_lineage_source(row, query.repository, true)
                        .ok()?,
                );
            }
            result
                .edges
                .push((query.revision.clone(), reference, kind.to_owned()));
        }
        Some(result)
    }

    /// Select frozen scorer outputs only for the exact snapshots already admitted at hop one.
    pub(crate) async fn verify_lineage(
        &self,
        query: &LineageQuery,
        lineage: &mut LineageRead,
        index: &BTreeMap<&str, Vec<&ObjectRow>>,
        cas_dir: &std::path::Path,
        budget: &mut RelationArchiveBudget,
    ) {
        use evertrace_domain::{query::SNAPSHOT_VERIFICATION_RESULT, semantic::ResultScope};
        const ROW_PREFIX: &str = "object:work:result_evidence:";
        const CANDIDATE_LIMIT: usize = 32;
        let snapshots: BTreeMap<_, _> = lineage
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("worktree_snapshot"))
            .filter_map(|row| Some((row.source_ref.clone()?, row.worktree_id.clone()?)))
            .collect();
        if snapshots.is_empty() {
            return;
        }
        let mut verified = BTreeSet::new();
        let mut checks_remaining = CANDIDATE_LIMIT.saturating_sub(lineage.rows.len());
        let mut metadata_bytes = evertrace_store::projections::READ_DEPENDENCY_BYTES;
        for (count, (_, rows)) in index
            .range(ROW_PREFIX..)
            .take_while(|(key, _)| key.starts_with(ROW_PREFIX))
            .enumerate()
        {
            if count == evertrace_store::projections::READ_DEPENDENCY_LIMIT
                || Instant::now() >= self.deadline
            {
                lineage.verification_missing = true;
                break;
            }
            let [row] = rows.as_slice() else {
                lineage.verification_missing = true;
                continue;
            };
            let Some(raw) = row.payload_json.as_deref() else {
                lineage.verification_missing = true;
                continue;
            };
            let Some(remaining) = metadata_bytes.checked_sub(raw.len() as u64) else {
                lineage.verification_missing = true;
                break;
            };
            metadata_bytes = remaining;
            let Ok(JournalPayload::ResultEvidenceRecorded(result)) = serde_json::from_str(raw)
            else {
                lineage.verification_missing = true;
                continue;
            };
            let run_revision = result.experiment_run_revision_id.to_string();
            let Some(run_row) =
                index
                    .get(run_revision.as_str())
                    .into_iter()
                    .flatten()
                    .find(|row| {
                        row.object_kind.as_deref() == Some("experiment_run")
                            && row.current_revision_id.as_deref() == Some(run_revision.as_str())
                    })
            else {
                continue;
            };
            let Some(run_json) = run_row.payload_json.as_deref() else {
                continue;
            };
            let Some(remaining) = metadata_bytes.checked_sub(run_json.len() as u64) else {
                lineage.verification_missing = true;
                break;
            };
            metadata_bytes = remaining;
            let Ok(JournalPayload::ExperimentRunRecorded(run)) = serde_json::from_str(run_json)
            else {
                lineage.verification_missing = true;
                continue;
            };
            let snapshot = run.code_snapshot_id.to_string();
            let Some(tree) = snapshots.get(&snapshot) else {
                continue;
            };
            // Denied or incomplete nominees also spend a check; they cannot make the access window unbounded.
            let Some(remaining) = checks_remaining.checked_sub(1) else {
                lineage.verification_missing = true;
                break;
            };
            checks_remaining = remaining;
            let key = result.result_evidence_id.to_string();
            let revision = result.revision_id.to_string();
            let current = index
                .get(key.as_str())
                .into_iter()
                .flatten()
                .filter(|row| row.object_kind.as_deref() == Some("result_evidence"))
                .max_by_key(|row| row.source_event_seq)
                .is_some_and(|row| row.current_revision_id.as_ref() == Some(&revision));
            if query.current_only && !current {
                continue;
            }
            if result.result_scope != ResultScope::Complete
                || self
                    .check_exact_record(&key, &revision, "result_evidence")
                    .await
                    .is_err()
                || !check_research_archive(
                    run_row,
                    self.writer,
                    cas_dir,
                    index,
                    budget,
                    self.deadline,
                )
                .await
                || !self
                    .reparse_snapshot_result(result, run, cas_dir, budget)
                    .await
            {
                lineage.verification_missing = true;
                continue;
            }
            let Ok(mut source) =
                evertrace_store::query::canonical_lineage_source(row, query.repository, current)
            else {
                lineage.verification_missing = true;
                continue;
            };
            source.worktree_id = Some(tree.clone());
            lineage.rows.push(source);
            verified.insert(snapshot.clone());
            lineage
                .edges
                .push((snapshot, revision, SNAPSHOT_VERIFICATION_RESULT.into()));
        }
        lineage.verification_missing |= verified.len() != snapshots.len();
    }

    async fn reparse_snapshot_result(
        &self,
        result: Box<evertrace_domain::semantic::ResultEvidence>,
        run: Box<evertrace_domain::work::ExperimentRun>,
        cas_dir: &std::path::Path,
        budget: &mut RelationArchiveBudget,
    ) -> bool {
        use crate::autoresearch::{
            RESULT_REPARSE_DECODED_BYTES, RESULT_REPARSE_ENCODED_BYTES, read_result_cohort,
        };
        let Some(encoded) = budget.encoded.checked_sub(RESULT_REPARSE_ENCODED_BYTES) else {
            return false;
        };
        let Some(decoded) = budget.decoded.checked_sub(RESULT_REPARSE_DECODED_BYTES) else {
            return false;
        };
        *budget = RelationArchiveBudget { encoded, decoded };
        let cas_dir = cas_dir.to_owned();
        let deadline = self.deadline;
        self.writer
            .read_handle()
            .read_blocking(move |cancel| {
                let verified = read_result_cohort(&cas_dir, &[(&result, &run)], &mut || {
                    cancel
                        .check()
                        .map_err(|_| evertrace_capture::CasError::ReadCancelled)?;
                    if Instant::now() < deadline {
                        Ok(())
                    } else {
                        Err(evertrace_capture::CasError::ReadCancelled)
                    }
                })
                .is_ok_and(|assessment| assessment.compatible);
                Ok(verified)
            })
            .await
            .unwrap_or_default()
    }
}

/// Bulk admission for reciprocal, unscoped observation/receipt pairs only. Their physical scopes still
/// come from the original live source assessment. Scoped or unfamiliar closures use the ordinary reader.
pub(crate) async fn search_observation_access<'a>(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    snapshot: &'a evertrace_store::ProjectionSnapshot,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
    deadline: Instant,
) -> BTreeMap<&'a str, bool> {
    use evertrace_domain::query::METADATA_READ_LIMIT;
    use evertrace_store::projections::ObjectDeletionCandidateAdmissionView;
    let mut sources = snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_observation"));
    let mut decisions = BTreeMap::new();
    loop {
        let pairs: Vec<_> = sources
            .by_ref()
            .take_while(|_| Instant::now() < deadline)
            .filter_map(|row| search_observation_pair(row, index))
            .take(usize::from(METADATA_READ_LIMIT) / 2)
            .collect();
        if pairs.is_empty() || Instant::now() >= deadline {
            break;
        }
        let rows: Vec<_> = pairs
            .iter()
            .flat_map(|(observation, receipt, _)| [*observation, *receipt])
            .collect();
        let Ok((denied, _)) = crate::session_import::source_rows_read_assessment(
            writer,
            authority,
            &snapshot.rows,
            &rows,
            None,
            Some(deadline),
        )
        .await
        else {
            continue;
        };
        let mut references: Vec<_> = pairs.iter().map(|(_, _, id)| (*id).to_owned()).collect();
        references.sort_unstable();
        references.dedup();
        let Ok(deletion) =
            ObjectDeletionCandidateAdmissionView::for_source_refs(snapshot, &references)
        else {
            continue;
        };
        for (observation, receipt, reference) in pairs {
            if let Ok(suppressed) = deletion.source_refs_suppressed(&[reference.to_owned()]) {
                let allowed = !suppressed
                    && !denied.contains(&observation.row_id)
                    && !denied.contains(&receipt.row_id);
                decisions.insert(observation.row_id.as_str(), allowed);
                decisions.insert(receipt.row_id.as_str(), allowed);
            }
        }
    }
    decisions
}

fn search_observation_pair<'a>(
    row: &'a ObjectRow,
    index: &BTreeMap<&str, Vec<&'a ObjectRow>>,
) -> Option<(&'a ObjectRow, &'a ObjectRow, &'a str)> {
    let unscoped = |row: &ObjectRow| {
        row.task_id.is_none() && row.repository_id.is_none() && row.worktree_id.is_none()
    };
    let id = row.object_id.as_deref()?;
    if !unscoped(row) || !matches!(index.get(id)?.as_slice(), [unique] if unique.row_id==row.row_id)
    {
        return None;
    }
    let JournalPayload::SourceObservationRecorded(observation) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    let receipt_id = observation.source_receipt_ref.to_string();
    let [receipt_row] = index.get(receipt_id.as_str())?.as_slice() else {
        return None;
    };
    if !unscoped(receipt_row)
        || receipt_row.object_kind.as_deref() != Some("source_receipt")
        || receipt_row.object_id.as_ref() != Some(&receipt_id)
    {
        return None;
    }
    let JournalPayload::SourceReceiptRecorded(receipt) =
        serde_json::from_str(receipt_row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    (observation.source_observation_id.to_string() == id
        && receipt.source_receipt_id == observation.source_receipt_ref
        && receipt.source_observation_id == observation.source_observation_id
        && receipt.source_instance_id == observation.source_instance_id
        && receipt.source_revision == observation.source_revision
        && observation.validate().is_ok()
        && receipt.validate().is_ok())
    .then_some((row, *receipt_row, id))
}

/// Assess only the canonical source and repository closure; observation recording belongs to callers.
pub(crate) async fn check_source_access(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    all_rows: &[ObjectRow],
    rows: &[&ObjectRow],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    check_source_access_split(writer, authority, all_rows, rows, rows, None, deadline).await
}

/// `source_rows` may omit already admitted source leaves from the same request, never object scopes.
/// A search index locates row facts only; repository authority is always read fresh.
pub(crate) async fn check_source_access_split(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    all_rows: &[ObjectRow],
    rows: &[&ObjectRow],
    source_rows: &[&ObjectRow],
    index: Option<&BTreeMap<&str, Vec<&ObjectRow>>>,
    deadline: Instant,
) -> Result<(), ErrorCode> {
    let empty_lookup = BTreeMap::new();
    for chunk in source_rows.chunks(usize::from(evertrace_domain::query::METADATA_READ_LIMIT)) {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted);
        }
        // Only evidence surfaces join another observation row here. Receipt and
        // digest assessment still receive their unchanged canonical inputs.
        let lookup = (!chunk
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("evidence_surface")))
        .then_some(&empty_lookup);
        if !crate::session_import::source_rows_read_assessment(
            writer,
            authority,
            all_rows,
            chunk,
            lookup,
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
    use crate::repository::row_repository_contexts_from_scopes;
    let scopes = if let Some(index) = index {
        let requested = rows
            .iter()
            .flat_map(|row| [row.task_id.as_deref(), row.worktree_id.as_deref()])
            .flatten()
            .collect::<BTreeSet<_>>();
        let scope_rows = requested.into_iter().flat_map(|reference| {
            index
                .get(reference)
                .into_iter()
                .flatten()
                .copied()
                .filter(move |row| row.object_id.as_deref() == Some(reference))
        });
        row_repository_contexts_from_scopes(scope_rows, rows)
    } else {
        row_repository_contexts_from_scopes(all_rows.iter(), rows)
    }
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

    async fn check_exact_record(
        &self,
        key: &str,
        revision: &str,
        kind: &str,
    ) -> Result<Box<StoredFieldsContext>, ErrorCode> {
        self.check(
            ExactReadQuery::Record(ExactRecordQuery {
                reference: ExactRecordRef {
                    stable_key: key.to_owned(),
                    revision_ref: Some(revision.to_owned()),
                },
                field: None,
                range: None,
                expected_data_identity: None,
                expected_selection: None,
            }),
            revision,
            kind,
        )
        .await
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
