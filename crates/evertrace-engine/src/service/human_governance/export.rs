use super::*;
use crate::search::read_context::LiveEpisodeRead;
use evertrace_capture::confined_read::ConfinedRoot;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_SELECTIONS: usize = 64;
pub(super) use evertrace_capture::cas::{
    PROTECTED_CONTENT_MAX_DECODED_BYTES as MAX_DECODED_BYTES,
    PROTECTED_CONTENT_MAX_ENCODED_BYTES as MAX_ENCODED_BYTES,
};
use evertrace_store::projections::{
    READ_DEPENDENCY_BYTES as MAX_METADATA_BYTES, READ_DEPENDENCY_LIMIT as MAX_DEPENDENCIES,
};
const MAX_OUTPUT_BYTES: u64 = 160 * 1024 * 1024;
const EXPORT_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct HumanExportSelection {
    pub object_ref: String,
    pub expected_revision_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanExportStatus {
    Published,
    PublicationUncertain,
    Conflict,
    Denied,
    Failed,
}

#[derive(Clone, Debug)]
pub struct HumanExportResult {
    pub status: HumanExportStatus,
    pub path: Option<String>,
    pub frontier: u64,
    pub object_count: u16,
    pub total_bytes: u64,
    pub reason: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Failure {
    Conflict,
    Denied,
    Limit,
    Corrupt,
    Io,
}

type ExportResult<T> = Result<T, Failure>;

struct Selection {
    rows: Vec<ObjectRow>,
    dependencies: BTreeMap<String, Vec<ObjectRow>>,
}

pub(super) struct SearchReadIndex<'a> {
    references: BTreeMap<&'a str, Vec<&'a ObjectRow>>,
    pub(super) live_episode: Option<LiveEpisodeRead>,
}

impl<'a> std::ops::Deref for SearchReadIndex<'a> {
    type Target = BTreeMap<&'a str, Vec<&'a ObjectRow>>;
    fn deref(&self) -> &Self::Target {
        &self.references
    }
}

impl<'a> SearchReadIndex<'a> {
    pub(super) fn new(
        snapshot: &'a ProjectionSnapshot,
        facets: &evertrace_domain::query::QueryFacetSet,
        selection: evertrace_domain::query::MemoryScopeSelection,
        deadline: Instant,
    ) -> ExportResult<Self> {
        let references = presentation_index(snapshot, deadline)?;
        let live_episode =
            LiveEpisodeRead::for_relation(snapshot, &references, facets, selection, deadline);
        Ok(Self {
            references,
            live_episode,
        })
    }
}

#[derive(Clone, Copy)]
enum ReadUse<'a> {
    Detail,
    Search(
        Option<&'a LiveEpisodeRead>,
        Option<&'a BTreeMap<&'a str, bool>>,
    ),
}

impl HumanGovernanceService {
    pub async fn export(&self, selections: Vec<HumanExportSelection>) -> HumanExportResult {
        let deadline = Instant::now() + EXPORT_DEADLINE;
        let mut result = HumanExportResult {
            status: HumanExportStatus::Failed,
            path: None,
            frontier: 0,
            object_count: 0,
            total_bytes: 0,
            reason: None,
        };
        let outcome = self.export_inner(selections, deadline, &mut result).await;
        if let Err(failure) = outcome {
            result.status = match failure {
                Failure::Conflict => HumanExportStatus::Conflict,
                Failure::Denied => HumanExportStatus::Denied,
                _ => HumanExportStatus::Failed,
            };
            result.reason = Some(match failure {
                Failure::Conflict => "selected_content_changed",
                Failure::Denied => "content_read_denied",
                Failure::Limit => "export_budget_exceeded",
                Failure::Corrupt => "protected_content_unavailable_or_corrupt",
                Failure::Io => "export_filesystem_failure",
            });
        }
        result
    }

    async fn export_inner(
        &self,
        selections: Vec<HumanExportSelection>,
        deadline: Instant,
        result: &mut HumanExportResult,
    ) -> ExportResult<()> {
        if selections.is_empty() || selections.len() > MAX_SELECTIONS {
            return Err(Failure::Limit);
        }
        let runtime = self.runtime_snapshot.as_ref().ok_or(Failure::Denied)?;
        let data_dir = runtime.data_dir().map_err(|_| Failure::Io)?.to_owned();
        let cas_dir = runtime.cas_dir.clone();
        let snapshot = self.writer.project().await.map_err(|_| Failure::Io)?;
        result.frontier = snapshot.frontier;
        let selection = select(&snapshot, &selections, deadline)?;
        result.object_count = selection.rows.len() as u16;
        self.selected_access(&snapshot, &selection, None, deadline)
            .await?;
        let rows = selection.rows.clone();
        let frontier = snapshot.frontier;
        // CAS decompression and filesystem writes never run inside the Writer actor.
        let mut stage = tokio::task::spawn_blocking(move || {
            stage(&data_dir, &cas_dir, &snapshot, &rows, frontier, deadline)
        })
        .await
        .map_err(|_| Failure::Io)??;
        result.total_bytes = stage.bytes;
        let current = self.writer.project().await.map_err(|_| Failure::Io)?;
        let reselected = select(&current, &selections, deadline)?;
        if selection.rows != reselected.rows || selection.dependencies != reselected.dependencies {
            return Err(Failure::Conflict);
        }
        self.selected_access(&current, &reselected, None, deadline)
            .await?;
        check_deadline(deadline)?;
        let publication = tokio::task::spawn_blocking(move || stage.publish(deadline))
            .await
            .map_err(|_| Failure::Io)??;
        result.path = Some(publication.0);
        result.status = if publication.1 {
            HumanExportStatus::Published
        } else {
            HumanExportStatus::PublicationUncertain
        };
        result.reason = (!publication.1).then_some("publication_durability_unconfirmed");
        Ok(())
    }

    async fn selected_access(
        &self,
        snapshot: &ProjectionSnapshot,
        selection: &Selection,
        sources: Option<&BTreeMap<&str, bool>>,
        deadline: Instant,
    ) -> ExportResult<()> {
        let mut rows = selection.rows.iter().collect::<Vec<_>>();
        rows.extend(selection.dependencies.values().flatten());
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        rows.dedup_by(|left, right| left.row_id == right.row_id);
        let mut unresolved = Vec::new();
        let source_rows = if let Some(sources) = sources {
            for row in &rows {
                match sources.get(row.row_id.as_str()) {
                    Some(false) => return Err(Failure::Denied),
                    Some(true) => {}
                    None => unresolved.push(*row),
                }
            }
            unresolved.as_slice()
        } else {
            rows.as_slice()
        };
        self.source_repository_access(&snapshot.rows, &rows, source_rows, deadline)
            .await?;
        let observations = source_rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
            .filter_map(|row| row.object_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for refs in observations.chunks(MAX_SELECTIONS) {
            if ObjectDeletionCandidateAdmissionView::for_source_refs(snapshot, refs)
                .and_then(|view| view.source_refs_suppressed(refs))
                .map_err(|_| Failure::Corrupt)?
            {
                return Err(Failure::Denied);
            }
        }
        check_deadline(deadline)
    }

    async fn source_repository_access(
        &self,
        all_rows: &[ObjectRow],
        rows: &[&ObjectRow],
        source_rows: &[&ObjectRow],
        deadline: Instant,
    ) -> ExportResult<()> {
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        crate::search::read_context::check_source_access_split(
            &self.writer,
            &crate::repository::RepositoryReadAuthority::retained(report.as_ref()),
            all_rows,
            rows,
            source_rows,
            deadline,
        )
        .await
        .map_err(|code| match code {
            evertrace_domain::error::ErrorCode::Untrusted => Failure::Denied,
            evertrace_domain::error::ErrorCode::ResourceExhausted => Failure::Limit,
            _ => Failure::Corrupt,
        })
    }

    // A Human detail may select an immutable historical row. Reuse the export
    // dependency and access contract, without export's current-only selection
    // rule or any CAS/output operation.
    pub(super) async fn readable_row(
        &self,
        snapshot: &ProjectionSnapshot,
        row: &ObjectRow,
        deadline: Instant,
    ) -> Result<(), Failure> {
        let index = presentation_index(snapshot, deadline)?;
        self.readable_indexed_row(snapshot, row, &index, deadline)
            .await
    }

    pub(super) async fn readable_indexed_row(
        &self,
        snapshot: &ProjectionSnapshot,
        row: &ObjectRow,
        index: &BTreeMap<&str, Vec<&ObjectRow>>,
        deadline: Instant,
    ) -> Result<(), Failure> {
        self.readable_with_dependencies(snapshot, row, index, ReadUse::Detail, deadline)
            .await
    }

    pub(super) async fn readable_search_row(
        &self,
        snapshot: &ProjectionSnapshot,
        row: &ObjectRow,
        index: &SearchReadIndex<'_>,
        sources: Option<&BTreeMap<&str, bool>>,
        deadline: Instant,
    ) -> Result<(), Failure> {
        let live = index
            .live_episode
            .as_ref()
            .filter(|proof| proof.contains(row));
        self.readable_with_dependencies(
            snapshot,
            row,
            index,
            ReadUse::Search(live, sources),
            deadline,
        )
        .await
    }

    async fn readable_with_dependencies(
        &self,
        snapshot: &ProjectionSnapshot,
        row: &ObjectRow,
        index: &BTreeMap<&str, Vec<&ObjectRow>>,
        purpose: ReadUse<'_>,
        deadline: Instant,
    ) -> Result<(), Failure> {
        let for_search = matches!(purpose, ReadUse::Search(..));
        let (live_episode, sources) = match purpose {
            ReadUse::Search(live, sources) => (live, sources),
            ReadUse::Detail => (None, None),
        };
        let mut charged = BTreeSet::new();
        let mut remaining = MAX_METADATA_BYTES;
        charge_metadata(row, &mut charged, &mut remaining, deadline)?;
        let payload = decode(row)?;
        let mut root = row.clone();
        let member_task = if for_search
            && (live_episode.is_some() || independent_search_member(row, &payload, index)?)
        {
            // Only authorization coordinates change; the original Task and all its roots stay in the closure.
            root.task_id.take()
        } else {
            None
        };
        let references = |row: &ObjectRow, payload: &JournalPayload| {
            let mut refs = dependencies_for(row, payload);
            if for_search && let JournalPayload::WorkstreamRecorded(work) = payload {
                for id in work
                    .parent_workstream_id
                    .iter()
                    .chain(&work.dependency_workstream_ids)
                {
                    let reference = id.to_string();
                    let Some([linked]) = index.get(reference.as_str()).map(Vec::as_slice) else {
                        return Err(Failure::Denied);
                    };
                    if linked.object_kind.as_deref() != Some("workstream")
                        || linked.object_id.as_deref() != Some(reference.as_str())
                        || linked.task_id.as_deref() != Some(work.task_id.to_string().as_str())
                    {
                        return Err(Failure::Denied);
                    }
                    refs.insert(reference);
                }
            }
            Ok(refs)
        };
        let mut pending = references(row, &payload)?;
        if let Some(live) = live_episode {
            pending.extend(
                live.sources
                    .as_ref()
                    .ok_or(Failure::Denied)?
                    .iter()
                    .cloned(),
            );
        }
        let dependencies = collect_dependencies(
            index,
            pending,
            &mut charged,
            &mut remaining,
            deadline,
            references,
            |row, payload| {
                member_task
                    .as_deref()
                    .is_some_and(|task| row.task_id.as_deref() == Some(task))
                    && match payload {
                        JournalPayload::TaskRecorded(task) => {
                            row.object_id.as_deref() == Some(task.task_id.to_string().as_str())
                        }
                        JournalPayload::WorkstreamRecorded(work) => {
                            independently_scoped_workstream(row, work)
                                || live_episode
                                    .is_some_and(|live| row.row_id == live.workstream_row)
                        }
                        _ => false,
                    }
            },
        )?;
        self.selected_access(
            snapshot,
            &Selection {
                rows: vec![root],
                dependencies,
            },
            sources,
            deadline,
        )
        .await
    }
}

fn independent_search_member(
    row: &ObjectRow,
    payload: &JournalPayload,
    index: &BTreeMap<&str, Vec<&ObjectRow>>,
) -> ExportResult<bool> {
    use evertrace_domain::work::{AttemptExecutionStatus, EpisodeLifecycle};
    // Only shapes whose actual dependencies are covered by the canonical read closure.
    let (task, stream, repository) = match payload {
        JournalPayload::WorkstreamRecorded(value) => {
            // The indexed goal text can use exact lineage observations without reading the shared lane
            // or interpreting its active Episode. Other Work candidates still need their own closure.
            return Ok(independently_scoped_workstream(row, value)
                || workstream_scope_identity(row, value)
                    && !value.worktree_lineage_refs.is_empty()
                    && value.worktree_lineage_refs.iter().all(|reference| {
                        let mut observations = index
                            .get(reference.as_str())
                            .into_iter()
                            .flatten()
                            .filter(|row| {
                                row.row_class == Some(ObjectRowClass::Object)
                                    && row.object_kind.as_deref() == Some("source_observation")
                                    && row.object_id.as_ref() == Some(reference)
                            });
                        reference
                            .parse::<evertrace_domain::ids::SourceObservationId>()
                            .is_ok()
                            && observations.next().is_some()
                            && observations.next().is_none()
                    }));
        }
        JournalPayload::WorkEpisodeRecorded(value)
            if value.lifecycle_status == EpisodeLifecycle::Closed
                && value.execution_lane_ids.is_empty()
                && value.attempt_ids.is_empty()
                && value.competing_attempt_group_ids.is_empty()
                && value.worktree_transition_refs.is_empty()
                && value.interruption_refs.is_empty()
                && value.completed_outcome_refs.is_empty()
                && value.selected_outcome_refs.is_empty()
                && value.checkpoint_refs.is_empty()
                && value.capture_gap_refs.is_empty()
                && value.capture_outage_refs.is_empty()
                && value.work_artifact_refs.is_empty()
                && value.segmentation_correction_refs.is_empty() =>
        {
            (
                value.task_id,
                value.workstream_id,
                value.repository_instance_id,
            )
        }
        JournalPayload::AttemptRecorded(value)
            if value.execution_status == AttemptExecutionStatus::Proposed
                && value.revision_generation == 1
                && value.resume_state_assessment.is_none()
                && value.composed_from_attempt_ids.is_empty()
                && value.competing_group_ids.is_empty()
                && value.worktree_transition_refs.is_empty()
                && value.work_binding_revision_refs.is_empty()
                && value.strategy_contract.search_policy_ref.is_none()
                && value.strategy_contract.objective_ref.is_none()
                && value.strategy_contract.target_refs.as_slice()
                    == [value.workstream_id.to_string()] =>
        {
            (
                value.task_id,
                value.workstream_id,
                value.repository_instance_id,
            )
        }
        _ => return Ok(false),
    };
    let Some(repository) = repository else {
        return Ok(false);
    };
    let stream_key = stream.to_string();
    if row.repository_id.as_deref() != Some(repository.to_string().as_str())
        || row.task_id.as_deref() != Some(task.to_string().as_str())
        || row.workstream_id.as_deref() != Some(stream_key.as_str())
    {
        return Ok(false);
    }
    let Some([parent]) = index.get(stream_key.as_str()).map(Vec::as_slice) else {
        return Ok(false);
    };
    let JournalPayload::WorkstreamRecorded(work) = decode(parent)? else {
        return Ok(false);
    };
    Ok(work.workstream_id == stream
        && work.task_id == task
        && work.repository_instance_id == Some(repository)
        && independently_scoped_workstream(parent, &work))
}

fn independently_scoped_workstream(
    row: &ObjectRow,
    work: &evertrace_domain::work::Workstream,
) -> bool {
    workstream_scope_identity(row, work)
        && work.worktree_lineage_refs.is_empty()
        && work.active_episode_id.is_none()
        && work.execution_lane_ids.is_empty()
}

fn workstream_scope_identity(row: &ObjectRow, work: &evertrace_domain::work::Workstream) -> bool {
    work.repository_instance_id
        .is_some_and(|id| row.repository_id.as_deref() == Some(id.to_string().as_str()))
        && row.task_id.as_deref() == Some(work.task_id.to_string().as_str())
        && row.object_id.as_ref() == row.workstream_id.as_ref()
        && row.object_id.as_deref() == Some(work.workstream_id.to_string().as_str())
}

pub(super) fn presentation_index(
    snapshot: &ProjectionSnapshot,
    deadline: Instant,
) -> ExportResult<BTreeMap<&str, Vec<&ObjectRow>>> {
    let mut index = BTreeMap::<&str, Vec<&ObjectRow>>::new();
    for candidate in snapshot.data_rows() {
        check_deadline(deadline)?;
        for key in [
            Some(candidate.row_id.as_str()),
            candidate.object_id.as_deref(),
            candidate.current_revision_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        {
            index.entry(key).or_default().push(candidate);
        }
    }
    Ok(index)
}

pub(super) fn check_deadline(deadline: Instant) -> ExportResult<()> {
    if Instant::now() >= deadline {
        Err(Failure::Limit)
    } else {
        Ok(())
    }
}

fn decode(row: &ObjectRow) -> ExportResult<JournalPayload> {
    let payload: JournalPayload =
        serde_json::from_str(row.payload_json.as_deref().ok_or(Failure::Corrupt)?)
            .map_err(|_| Failure::Corrupt)?;
    payload.validate().map_err(|_| Failure::Corrupt)?;
    Ok(payload)
}

fn exportable(payload: &JournalPayload) -> bool {
    matches!(
        payload,
        JournalPayload::AtomRecorded(_)
            | JournalPayload::ProcedureRevisionRecorded(_)
            | JournalPayload::RevisionProposalRecorded(_)
            | JournalPayload::CoreMembershipRecorded(_)
            | JournalPayload::SemanticDigestRecorded(_)
            | JournalPayload::SourceReceiptRecorded(_)
            | JournalPayload::SourceObservationRecorded(_)
            | JournalPayload::TaskRecorded(_)
            | JournalPayload::WorkstreamRecorded(_)
            | JournalPayload::WorkBindingRecorded(_)
            | JournalPayload::AttemptRecorded(_)
            | JournalPayload::CompetingAttemptGroupRecorded(_)
            | JournalPayload::OperationBurstRecorded(_)
            | JournalPayload::WorkEpisodeRecorded(_)
            | JournalPayload::WorkCheckpointRecorded(_)
            | JournalPayload::ExecutionLaneRecorded(_)
            | JournalPayload::CaptureReceiptRecorded(_)
            | JournalPayload::ExperimentRunRecorded(_)
            | JournalPayload::ResultEvidenceRecorded(_)
            | JournalPayload::WorkArtifactRecorded(_)
            | JournalPayload::OperationDerived(_)
            | JournalPayload::ScopeEffectDerived(_)
            | JournalPayload::RepositoryInstanceRecorded(_)
            | JournalPayload::WorktreeInstanceRecorded(_)
            | JournalPayload::WorktreeSnapshotRecorded(_)
            | JournalPayload::WorktreeTransitionRecorded(_)
            | JournalPayload::IntegrationEventRecorded(_)
            | JournalPayload::SegmentationCorrectionRecorded(_)
    )
}

fn select(
    snapshot: &ProjectionSnapshot,
    selections: &[HumanExportSelection],
    deadline: Instant,
) -> ExportResult<Selection> {
    if selections.is_empty() || selections.len() > MAX_SELECTIONS {
        return Err(Failure::Limit);
    }
    let mut index = BTreeMap::<&str, Vec<&ObjectRow>>::new();
    for row in snapshot
        .data_rows()
        .filter(|row| surface_matches(HumanSurface::Explorer, row))
    {
        check_deadline(deadline)?;
        for key in [
            Some(row.row_id.as_str()),
            row.object_id.as_deref(),
            row.current_revision_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        {
            index.entry(key).or_default().push(row);
        }
    }
    let mut rows = BTreeMap::new();
    let mut pending = BTreeSet::new();
    let mut remaining = MAX_METADATA_BYTES;
    let mut charged = BTreeSet::new();
    let mut current = BTreeMap::new();
    let mut binding_view = None;
    for selected in selections {
        check_deadline(deadline)?;
        if !valid_ref(&selected.object_ref) {
            return Err(Failure::Denied);
        }
        let candidates = index
            .get(selected.object_ref.as_str())
            .ok_or(Failure::Conflict)?;
        let first = *candidates.first().ok_or(Failure::Conflict)?;
        let kind = first.object_kind.as_deref().ok_or(Failure::Denied)?;
        let id = first.object_id.as_deref().ok_or(Failure::Denied)?;
        if kind == "capture_receipt_revision" {
            return Err(Failure::Conflict);
        }
        if candidates
            .iter()
            .any(|row| row.object_kind != first.object_kind || row.object_id != first.object_id)
        {
            return Err(Failure::Conflict);
        }
        let row = if let Some(row) = current.get(&(kind, id)) {
            *row
        } else {
            let lineage = index
                .get(id)
                .ok_or(Failure::Corrupt)?
                .iter()
                .copied()
                .filter(|row| row.object_kind.as_deref() == Some(kind))
                .collect::<Vec<_>>();
            for row in &lineage {
                charge_metadata(row, &mut charged, &mut remaining, deadline)?;
            }
            let revision = if kind == "work_binding" {
                if binding_view.is_none() {
                    // Binding row identity is its revision, not its Operation. This
                    // existing view owns that lineage; bound its family before decoding.
                    let mut packet = ProjectionSnapshot {
                        frontier: snapshot.frontier,
                        rows: Vec::new(),
                    };
                    for row in snapshot
                        .data_rows()
                        .filter(|row| row.object_kind.as_deref() == Some("work_binding"))
                    {
                        charge_metadata(row, &mut charged, &mut remaining, deadline)?;
                        packet.rows.push(row.clone());
                    }
                    binding_view = Some(
                        evertrace_store::WorkBindingCurrentView::from_snapshot(&packet)
                            .map_err(|_| Failure::Corrupt)?,
                    );
                }
                let JournalPayload::WorkBindingRecorded(binding) = decode(first)? else {
                    return Err(Failure::Corrupt);
                };
                binding_view
                    .as_ref()
                    .and_then(|view| view.bindings.get(&binding.operation_id))
                    .map(|value| value.work_binding_revision_id.to_string())
                    .ok_or(Failure::Conflict)?
            } else {
                let packet = ProjectionSnapshot {
                    frontier: snapshot.frontier,
                    rows: lineage.iter().map(|row| (*row).clone()).collect(),
                };
                selected_current_revision(&packet, kind, id)?
            };
            let row = lineage
                .into_iter()
                .find(|row| row.current_revision_id.as_deref() == Some(revision.as_str()))
                .ok_or(Failure::Conflict)?;
            current.insert((kind, id), row);
            row
        };
        // A logical identity may resolve to current; an explicitly selected old
        // row/revision must never silently move to its successor.
        if !candidates
            .iter()
            .any(|candidate| candidate.row_id == row.row_id)
        {
            return Err(Failure::Conflict);
        }
        if selected
            .expected_revision_ref
            .as_ref()
            .is_some_and(|expected| row.current_revision_id.as_ref() != Some(expected))
        {
            return Err(Failure::Conflict);
        }
        let payload = decode(row)?;
        if !exportable(&payload) {
            return Err(Failure::Denied);
        }
        pending.extend(dependencies_for(row, &payload));
        rows.insert(row.row_id.clone(), row.clone());
    }
    let dependencies = collect_dependencies(
        &index,
        pending,
        &mut charged,
        &mut remaining,
        deadline,
        |row, payload| Ok(dependencies_for(row, payload)),
        |_, _| false,
    )?;
    Ok(Selection {
        rows: rows.into_values().collect(),
        dependencies,
    })
}

fn collect_dependencies(
    index: &BTreeMap<&str, Vec<&ObjectRow>>,
    mut pending: BTreeSet<String>,
    charged: &mut BTreeSet<String>,
    remaining: &mut u64,
    deadline: Instant,
    references: impl Fn(&ObjectRow, &JournalPayload) -> ExportResult<BTreeSet<String>>,
    structural_scope: impl Fn(&ObjectRow, &JournalPayload) -> bool,
) -> ExportResult<BTreeMap<String, Vec<ObjectRow>>> {
    let mut dependencies = BTreeMap::new();
    // The bounded dependency closure is checked, never exported implicitly.
    while let Some(reference) = pending.pop_first() {
        check_deadline(deadline)?;
        if dependencies.contains_key(&reference) {
            continue;
        }
        if dependencies.len() + pending.len() >= MAX_DEPENDENCIES {
            return Err(Failure::Limit);
        }
        let mut referenced = Vec::new();
        for row in index.get(reference.as_str()).into_iter().flatten() {
            charge_metadata(row, charged, remaining, deadline)?;
            let payload = decode(row)?;
            pending.extend(references(row, &payload)?);
            let mut authorization = (*row).clone();
            if structural_scope(row, &payload) {
                authorization.task_id = None;
            }
            referenced.push(authorization);
        }
        dependencies.insert(reference, referenced);
    }
    Ok(dependencies)
}

fn charge_metadata(
    row: &ObjectRow,
    charged: &mut BTreeSet<String>,
    remaining: &mut u64,
    deadline: Instant,
) -> ExportResult<()> {
    check_deadline(deadline)?;
    if charged.insert(row.row_id.clone()) && charged.len() > MAX_DEPENDENCIES {
        return Err(Failure::Limit);
    }
    // Different references can retain the same row; each retained copy consumes
    // the metadata budget even though it is only one distinct dependency.
    *remaining = remaining
        .checked_sub(row.payload_json.as_ref().map_or(0, |payload| payload.len()) as u64)
        .ok_or(Failure::Limit)?;
    Ok(())
}

// Only the selected, already-budgeted lineage enters each existing authority.
// No current reducer, UUID ordering, or full-database semantic view is replicated here.
fn selected_current_revision(
    packet: &ProjectionSnapshot,
    kind: &str,
    id: &str,
) -> ExportResult<String> {
    use evertrace_store::{
        AttemptCurrentView, AutoresearchCurrentView, EpisodeCurrentView, SegmentationCurrentState,
        SegmentationCurrentView,
    };
    macro_rules! from_view {
        ($view:ty, $map:ident, $revision:ident) => {
            <$view>::from_snapshot(packet)
                .map_err(|_| Failure::Corrupt)?
                .$map
                .get(&id.parse().map_err(|_| Failure::Corrupt)?)
                .map(|value| value.$revision.to_string())
                .ok_or(Failure::Conflict)
        };
    }
    match kind {
        "atom_revision" => from_view!(SemanticCurrentView, atoms, revision_id),
        "revision_proposal_revision" => {
            from_view!(SemanticCurrentView, proposals, proposal_revision_id)
        }
        "procedure_revision" => {
            let view =
                ProcedureUsageCurrentView::from_snapshot(packet).map_err(|_| Failure::Corrupt)?;
            packet
                .rows
                .iter()
                .filter_map(|row| row.current_revision_id.as_ref())
                .find(|revision| {
                    revision.parse().ok().is_some_and(|revision| {
                        view.current_procedure_by_revision(revision).is_some()
                    })
                })
                .cloned()
                .ok_or(Failure::Conflict)
        }
        "attempt" => from_view!(AttemptCurrentView, attempts, revision_id),
        "competing_attempt_group" => from_view!(AttemptCurrentView, competing_groups, revision_id),
        "work_episode" => from_view!(EpisodeCurrentView, episodes, revision_id),
        "operation_burst" => SegmentationCurrentState::from_snapshot(packet)
            .map_err(|_| Failure::Corrupt)?
            .current_burst(id.parse().map_err(|_| Failure::Corrupt)?)
            .map(|value| value.revision_id.to_string())
            .ok_or(Failure::Conflict),
        "operation" => SegmentationCurrentView::from_snapshot(packet)
            .map_err(|_| Failure::Corrupt)?
            .operation(id.parse().map_err(|_| Failure::Corrupt)?)
            .map(|value| format!("{}@{}", value.operation_id, value.operation_revision))
            .ok_or(Failure::Conflict),
        "experiment_run" => from_view!(AutoresearchCurrentView, runs, revision_id),
        "result_evidence" => from_view!(AutoresearchCurrentView, results, revision_id),
        "work_artifact" => AutoresearchCurrentView::from_snapshot(packet)
            .map_err(|_| Failure::Corrupt)?
            .artifacts
            .get(&id.parse().map_err(|_| Failure::Corrupt)?)
            .map(|value| value.revision.revision_id.to_string())
            .ok_or(Failure::Conflict),
        _ if packet.rows.len() == 1 => packet.rows[0]
            .current_revision_id
            .clone()
            .ok_or(Failure::Corrupt),
        _ => Err(Failure::Conflict),
    }
}

use evertrace_store::projections::read_dependencies_for as dependencies_for;

struct Stage {
    parent: ConfinedRoot,
    root: ConfinedRoot,
    locator: PathBuf,
    destination: String,
    files: Vec<(String, (u64, u64))>,
    bytes: u64,
    published: bool,
}

impl Stage {
    fn create(data: &Path) -> ExportResult<Self> {
        let exports_locator = data.join("exports");
        let data = ConfinedRoot::open_owned_private(data).map_err(|_| Failure::Io)?;
        let exports = data
            .proc_cwd_path()
            .map_err(|_| Failure::Io)?
            .join("exports");
        match DirBuilder::new().mode(0o700).create(&exports) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Failure::Io),
        }
        data.revalidate_stable().map_err(|_| Failure::Io)?;
        let parent = ConfinedRoot::open_owned_private(&exports_locator).map_err(|_| Failure::Io)?;
        let metadata = fs::symlink_metadata(&exports).map_err(|_| Failure::Io)?;
        if metadata.mode() & 0o777 != 0o700 {
            return Err(Failure::Io);
        }
        File::open(data.proc_cwd_path().map_err(|_| Failure::Io)?)
            .and_then(|file| file.sync_all())
            .map_err(|_| Failure::Io)?;
        let destination = format!("export-{}", RequestId::new_v7());
        let staging_name = format!(".staging-{destination}");
        let locator = exports_locator.join(&staging_name);
        parent.revalidate_stable().map_err(|_| Failure::Io)?;
        let held_staging = parent
            .proc_cwd_path()
            .map_err(|_| Failure::Io)?
            .join(&staging_name);
        DirBuilder::new()
            .mode(0o700)
            .create(&held_staging)
            .map_err(|_| Failure::Io)?;
        let created = fs::symlink_metadata(&held_staging).map_err(|_| Failure::Io)?;
        let root = ConfinedRoot::open_owned_private(&locator).map_err(|_| Failure::Io)?;
        if root.identity().device != created.dev() || root.identity().inode != created.ino() {
            return Err(Failure::Io);
        }
        Ok(Self {
            parent,
            root,
            locator,
            destination,
            files: Vec::new(),
            bytes: 0,
            published: false,
        })
    }

    fn write(&mut self, name: String, bytes: &[u8], deadline: Instant) -> ExportResult<()> {
        check_deadline(deadline)?;
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= MAX_OUTPUT_BYTES)
            .ok_or(Failure::Limit)?;
        self.root.revalidate_stable().map_err(|_| Failure::Io)?;
        let path = self
            .root
            .proc_cwd_path()
            .map_err(|_| Failure::Io)?
            .join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| Failure::Io)?;
        let identity = file.metadata().map_err(|_| Failure::Io)?;
        self.files.push((name, (identity.dev(), identity.ino())));
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| Failure::Io)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Failure::Io)?;
        check_deadline(deadline)
    }

    fn publish(&mut self, deadline: Instant) -> ExportResult<(String, bool)> {
        check_deadline(deadline)?;
        let target = self
            .locator
            .parent()
            .ok_or(Failure::Io)?
            .join(&self.destination);
        let rename = self
            .parent
            .publish_directory_noreplace(&self.root, &self.destination);
        let matches = ConfinedRoot::open_owned_private(&target).is_ok_and(|root| {
            root.identity().device == self.root.identity().device
                && root.identity().inode == self.root.identity().inode
        });
        // A post-rename failure is not evidence that no publication occurred.
        if !matches && rename.is_err() {
            if self.root.revalidate_stable().is_ok() {
                return Err(Failure::Io);
            }
            self.published = true;
            return Ok((target.to_string_lossy().into_owned(), false));
        }
        self.published = true;
        let synced = self
            .parent
            .proc_cwd_path()
            .ok()
            .is_some_and(|path| File::open(path).and_then(|file| file.sync_all()).is_ok());
        Ok((
            target.to_string_lossy().into_owned(),
            rename.is_ok() && matches && synced,
        ))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.published || self.root.revalidate_stable().is_err() {
            return;
        }
        if let Ok(path) = self.root.proc_cwd_path() {
            for (name, identity) in &self.files {
                let child = path.join(name);
                if fs::symlink_metadata(&child).is_ok_and(|metadata| {
                    metadata.is_file() && (metadata.dev(), metadata.ino()) == *identity
                }) {
                    let _ = fs::remove_file(child);
                }
            }
            if self.root.revalidate_stable().is_ok() {
                let _ = fs::remove_dir(&self.locator);
            }
        }
    }
}

pub(super) fn validate_source_archive(
    receipt: &evertrace_domain::evidence::SourceReceipt,
    observation: &evertrace_domain::evidence::SourceObservation,
    bytes: &[u8],
) -> ExportResult<()> {
    let mut verifier = evertrace_capture::cas::SourceArchiveVerifier::new(receipt, observation)
        .map_err(|_| Failure::Corrupt)?;
    verifier.update(bytes).map_err(|_| Failure::Corrupt)?;
    verifier.finish().map_err(|_| Failure::Corrupt)
}

fn stage(
    data: &Path,
    cas: &Path,
    snapshot: &ProjectionSnapshot,
    rows: &[ObjectRow],
    frontier: u64,
    deadline: Instant,
) -> ExportResult<Stage> {
    let mut stage = Stage::create(data)?;
    let mut cas_store = None;
    let mut encoded_remaining = MAX_ENCODED_BYTES;
    let mut decoded_remaining = MAX_DECODED_BYTES;
    for (index, row) in rows.iter().enumerate() {
        check_deadline(deadline)?;
        let payload = decode(row)?;
        let mut document = format!(
            concat!(
                "# EverTrace selected object\n\nFrontier: {}\n\nObject: {}\n\nRevision: {}\n\n",
                "Scope: {:?}\n\nLifecycle: {:?}; publication: {:?}; support: {:?}\n\n",
                "Complete stored content (selected object only):\n\n",
            ),
            frontier,
            row.object_id.as_deref().unwrap_or(&row.row_id),
            row.current_revision_id.as_deref().unwrap_or("none"),
            (&row.repository_id, &row.task_id, &row.workstream_id),
            row.lifecycle,
            row.publication_state,
            row.support_state
        );
        let json = serde_json::to_string_pretty(&payload).map_err(|_| Failure::Corrupt)?;
        let rendered_length = json.len() as u64 + 5 * json.lines().count() as u64;
        if stage.bytes + document.len() as u64 + rendered_length > MAX_OUTPUT_BYTES {
            return Err(Failure::Limit);
        }
        // Indented Markdown preserves every stored field without allowing payload fences to escape.
        for line in json.lines() {
            document.push_str("    ");
            document.push_str(line);
            document.push('\n');
        }
        let receipt = match &payload {
            JournalPayload::SourceReceiptRecorded(value) => Some(value.as_ref().clone()),
            JournalPayload::SourceObservationRecorded(value) => {
                let other = snapshot
                    .row(&format!(
                        "object:evidence:source_receipt:{}",
                        value.source_receipt_ref
                    ))
                    .ok_or(Failure::Corrupt)?;
                let JournalPayload::SourceReceiptRecorded(receipt) = decode(other)? else {
                    return Err(Failure::Corrupt);
                };
                Some(*receipt)
            }
            _ => None,
        };
        if let Some(receipt) = receipt {
            if cas_store.is_none() {
                cas_store = Some(CasStore::open_existing(cas).map_err(|_| Failure::Corrupt)?);
            }
            let cas = cas_store.as_ref().ok_or(Failure::Corrupt)?;
            let digest = CasStore::parse_digest(&receipt.cas_ref).map_err(|_| Failure::Corrupt)?;
            let (bytes, encoded) = cas
                .read_bounded(&digest, encoded_remaining, decoded_remaining)
                .map_err(|error| match error {
                    evertrace_capture::CasError::ReadBudgetExceeded => Failure::Limit,
                    _ => Failure::Corrupt,
                })?;
            encoded_remaining = encoded_remaining
                .checked_sub(encoded)
                .ok_or(Failure::Limit)?;
            decoded_remaining = decoded_remaining
                .checked_sub(bytes.len() as u64)
                .ok_or(Failure::Limit)?;
            let other = snapshot
                .row(&format!(
                    "object:evidence:source_observation:{}",
                    receipt.source_observation_id
                ))
                .ok_or(Failure::Corrupt)?;
            let JournalPayload::SourceObservationRecorded(observation) = decode(other)? else {
                return Err(Failure::Corrupt);
            };
            validate_source_archive(&receipt, &observation, &bytes)?;
            match std::str::from_utf8(&bytes) {
                Ok(text)
                    if !text
                        .chars()
                        .any(|ch| ch.is_control() && ch != '\n' && ch != '\t') =>
                {
                    if stage.bytes
                        + document.len() as u64
                        + text.len() as u64
                        + 4 * text.split_inclusive('\n').count() as u64
                        + 64
                        > MAX_OUTPUT_BYTES
                    {
                        return Err(Failure::Limit);
                    }
                    document.push_str("\n## Complete protected source\n\n");
                    for line in text.split_inclusive('\n') {
                        document.push_str("    ");
                        document.push_str(line);
                    }
                    document.push('\n');
                }
                _ => {
                    let attachment = format!("{:02}-protected.bin", index + 1);
                    document.push_str(&format!("\nComplete protected source bytes: [{attachment}]({attachment}) ({} bytes).\n", bytes.len()));
                    stage.write(attachment, &bytes, deadline)?;
                }
            }
        }
        stage.write(
            format!("{:02}-object.md", index + 1),
            document.as_bytes(),
            deadline,
        )?;
    }
    File::open(stage.root.proc_cwd_path().map_err(|_| Failure::Io)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| Failure::Io)?;
    Ok(stage)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("evertrace-export-test-{}", RequestId::new_v7()));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn export_revalidation_ignores_unrelated_append_but_tracks_selected_and_dependencies() {
        let id = evertrace_domain::ids::TaskId::new_v7();
        let dependency = evertrace_domain::ids::TaskId::new_v7();
        let task = evertrace_domain::work::Task {
            task_id: id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: vec![dependency.to_string()],
            canonical_goal: "Complete stored goal".into(),
            scope_memberships: vec![],
            identity_confidence: evertrace_domain::work::TaskIdentityConfidence::Provisional,
            lifecycle: evertrace_domain::work::TaskLifecycle::Active,
            continuation_of_task_id: None,
            split_from_task_id: None,
            split_into_task_ids: vec![],
            merged_from_task_ids: vec![],
            merged_into_task_id: None,
            created_at_us: 1,
            closed_at_us: None,
            source_watermark: 1,
        };
        let row = ObjectRow {
            row_id: format!("object:work:task:{id}"),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: Some(ObjectFamily::Work),
            object_kind: Some("task".into()),
            object_id: Some(id.to_string()),
            current_revision_id: Some(task.revision_id.to_string()),
            lifecycle: Some("open".into()),
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
            payload_json: Some(
                serde_json::to_string(&JournalPayload::TaskRecorded(Box::new(task)))
                    .unwrap()
                    .into(),
            ),
            source_event_seq: 1,
            projection_generation: 1,
        };
        let mut snapshot = ProjectionSnapshot {
            frontier: 1,
            rows: vec![row.clone()],
        };
        let selections = vec![HumanExportSelection {
            object_ref: id.to_string(),
            expected_revision_ref: None,
        }];
        let deadline = Instant::now() + EXPORT_DEADLINE;
        let selected = select(&snapshot, &selections, deadline).unwrap();
        let root = Root::new();
        let staged = stage(
            &root.0,
            &root.0.join("absent-cas"),
            &snapshot,
            &selected.rows,
            snapshot.frontier,
            deadline,
        )
        .unwrap();
        assert!(
            fs::read_to_string(staged.locator.join("01-object.md"))
                .unwrap()
                .contains("Complete stored goal")
        );
        drop(staged);
        snapshot.frontier += 1;
        let mut unrelated = row.clone();
        unrelated.row_id = "runtime:unrelated".into();
        unrelated.object_id = None;
        unrelated.current_revision_id = None;
        unrelated.row_class = Some(ObjectRowClass::Runtime);
        unrelated.object_kind = Some("config_audit".into());
        unrelated.payload_json = Some(
            serde_json::to_string(&JournalPayload::ConfigAudit(evertrace_store::ConfigAudit {
                config_version: 1,
                effective_config_hash: [0; 32],
                reload: None,
            }))
            .unwrap()
            .into(),
        );
        snapshot.rows.push(unrelated);
        let after = select(&snapshot, &selections, deadline).unwrap();
        assert_eq!(selected.rows, after.rows);
        assert_eq!(selected.dependencies, after.dependencies);
        snapshot.rows[0].source_event_seq += 1;
        assert_ne!(
            selected.rows,
            select(&snapshot, &selections, deadline).unwrap().rows
        );
        snapshot.rows[0] = row.clone();
        let mut related = row;
        related.object_id = Some(dependency.to_string());
        related.row_id = format!("object:work:task:{dependency}");
        related.current_revision_id = Some(RevisionId::new_v7().to_string());
        let JournalPayload::TaskRecorded(mut task) = decode(&related).unwrap() else {
            unreachable!()
        };
        task.task_id = dependency;
        task.revision_id = related
            .current_revision_id
            .as_ref()
            .unwrap()
            .parse()
            .unwrap();
        task.request_root_refs = vec!["source:user".into()];
        related.payload_json = Some(
            serde_json::to_string(&JournalPayload::TaskRecorded(task))
                .unwrap()
                .into(),
        );
        snapshot.rows.push(related);
        assert_ne!(
            selected.dependencies,
            select(&snapshot, &selections, deadline)
                .unwrap()
                .dependencies
        );
        snapshot.rows.remove(0);
        assert!(matches!(
            select(&snapshot, &selections, deadline),
            Err(Failure::Conflict)
        ));
        assert!(matches!(
            select(&snapshot, &selections, Instant::now()),
            Err(Failure::Limit)
        ));
    }

    #[test]
    fn export_publication_is_private_noreplace_and_failure_cleanup_is_owned() {
        let root = Root::new();
        let deadline = Instant::now() + EXPORT_DEADLINE;
        let mut first = Stage::create(&root.0).unwrap();
        first
            .write("01-object.md".into(), b"complete", deadline)
            .unwrap();
        let name = first.destination.clone();
        let published = first.publish(deadline).unwrap();
        assert!(published.1);
        drop(first);
        assert_eq!(
            fs::read(Path::new(&published.0).join("01-object.md")).unwrap(),
            b"complete"
        );
        let mut second = Stage::create(&root.0).unwrap();
        second.destination = name;
        let staging = second.locator.clone();
        second
            .write("01-object.md".into(), b"replacement", deadline)
            .unwrap();
        assert!(matches!(second.publish(deadline), Err(Failure::Io)));
        drop(second);
        assert!(!staging.exists());
        assert_eq!(
            fs::read(Path::new(&published.0).join("01-object.md")).unwrap(),
            b"complete"
        );
        let mut failed = Stage::create(&root.0).unwrap();
        let staging = failed.locator.clone();
        assert!(matches!(
            failed.write("01-object.md".into(), b"x", Instant::now()),
            Err(Failure::Limit)
        ));
        failed.bytes = MAX_OUTPUT_BYTES;
        assert!(matches!(
            failed.write("01-object.md".into(), b"x", deadline),
            Err(Failure::Limit)
        ));
        failed.bytes = 0;
        std::os::unix::fs::symlink(
            Path::new(&published.0).join("01-object.md"),
            staging.join("01-object.md"),
        )
        .unwrap();
        assert!(matches!(
            failed.write("01-object.md".into(), b"overwrite", deadline),
            Err(Failure::Io)
        ));
        drop(failed);
        assert!(
            fs::symlink_metadata(staging.join("01-object.md"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            fs::read(Path::new(&published.0).join("01-object.md")).unwrap(),
            b"complete"
        );
        let other = Root::new();
        std::os::unix::fs::symlink(root.0.join("exports"), other.0.join("exports")).unwrap();
        assert!(matches!(Stage::create(&other.0), Err(Failure::Io)));
    }
}
