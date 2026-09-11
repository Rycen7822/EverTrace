use super::*;
use evertrace_capture::confined_read::ConfinedRoot;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_SELECTIONS: usize = 64;
const MAX_DEPENDENCIES: usize = 4096;
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENCODED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 128 * 1024 * 1024;
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
enum Failure {
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
        self.export_access(&snapshot, &selection, deadline).await?;
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
        self.export_access(&current, &reselected, deadline).await?;
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

    async fn export_access(
        &self,
        snapshot: &ProjectionSnapshot,
        selection: &Selection,
        deadline: Instant,
    ) -> ExportResult<()> {
        let mut rows = selection.rows.iter().collect::<Vec<_>>();
        rows.extend(selection.dependencies.values().flatten());
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        rows.dedup_by(|left, right| left.row_id == right.row_id);
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        for chunk in rows.chunks(MAX_SELECTIONS) {
            check_deadline(deadline)?;
            if !crate::session_import::blocked_source_rows(
                &self.writer,
                report.as_ref(),
                snapshot,
                chunk,
                self.effective_config_hash,
            )
            .await
            .map_err(|_| Failure::Corrupt)?
            .is_empty()
            {
                return Err(Failure::Denied);
            }
        }
        let scopes = crate::repository::row_repository_contexts(snapshot, &rows)
            .map_err(|_| Failure::Corrupt)?;
        if !crate::repository::blocked_repositories(
            &self.writer,
            scopes.values().flatten().copied().collect(),
            report.as_ref(),
            self.effective_config_hash,
        )
        .await
        .map_err(|_| Failure::Corrupt)?
        .is_empty()
        {
            return Err(Failure::Denied);
        }
        let observations = rows
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
}

fn check_deadline(deadline: Instant) -> ExportResult<()> {
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
    let mut dependencies = BTreeMap::new();
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
    // The bounded dependency closure is checked, never exported implicitly.
    while let Some(reference) = pending.pop_first() {
        check_deadline(deadline)?;
        if dependencies.contains_key(&reference) {
            continue;
        }
        if dependencies.len() + pending.len() >= MAX_DEPENDENCIES {
            return Err(Failure::Limit);
        }
        let referenced = index.get(reference.as_str()).cloned().unwrap_or_default();
        for row in &referenced {
            charge_metadata(row, &mut charged, &mut remaining, deadline)?;
            pending.extend(dependencies_for(row, &decode(row)?));
        }
        dependencies.insert(reference, referenced.into_iter().cloned().collect());
    }
    Ok(Selection {
        rows: rows.into_values().collect(),
        dependencies,
    })
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
        .checked_sub(row.payload_json.as_ref().map_or(0, String::len) as u64)
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

fn dependencies_for(row: &ObjectRow, payload: &JournalPayload) -> BTreeSet<String> {
    let mut refs = [
        row.task_id.clone(),
        row.worktree_id.clone(),
        row.repository_id.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<BTreeSet<_>>();
    match payload {
        JournalPayload::OperationDerived(value) => {
            refs.insert(value.host_occurrence_id.to_string());
            refs.extend(value.execution_lane_id.map(|id| id.to_string()));
            refs.extend(
                value
                    .input_source_observation_refs
                    .iter()
                    .chain(&value.result_source_observation_refs)
                    .map(ToString::to_string),
            );
            refs.extend(value.scope_effect_ids.iter().map(ToString::to_string));
            refs.extend(value.artifact_refs.iter().map(ToString::to_string));
        }
        JournalPayload::ScopeEffectDerived(value) => {
            refs.insert(value.operation_id.to_string());
            refs.extend(value.repository_instance_id.map(|id| id.to_string()));
            refs.extend(value.worktree_instance_id.map(|id| id.to_string()));
            refs.extend(
                value
                    .pre_snapshot_id
                    .into_iter()
                    .chain(value.post_snapshot_id)
                    .map(|id| id.to_string()),
            );
            refs.extend(value.experiment_run_ids.iter().map(ToString::to_string));
            refs.extend(value.artifact_refs.iter().map(ToString::to_string));
            refs.extend(value.evidence_refs.iter().map(ToString::to_string));
        }
        JournalPayload::WorktreeInstanceRecorded(value) => {
            refs.insert(value.repository_instance_id.to_string());
            refs.extend(value.current_snapshot_id.map(|id| id.to_string()));
        }
        JournalPayload::WorktreeSnapshotRecorded(value) => {
            refs.insert(value.worktree_instance_id.to_string());
            refs.extend(value.evidence_refs.iter().cloned());
        }
        JournalPayload::WorktreeTransitionRecorded(value) => {
            refs.insert(value.from_worktree_instance_id.to_string());
            refs.insert(value.to_worktree_instance_id.to_string());
            refs.extend(
                value
                    .from_snapshot_id
                    .into_iter()
                    .chain(value.to_snapshot_id)
                    .map(|id| id.to_string()),
            );
            refs.extend(value.evidence_refs.iter().cloned());
        }
        JournalPayload::IntegrationEventRecorded(value) => {
            refs.insert(value.repository_instance_id.to_string());
            refs.insert(value.source_worktree_instance_id.to_string());
            refs.insert(value.destination_worktree_instance_id.to_string());
            refs.insert(value.source_snapshot_id.to_string());
            refs.insert(value.destination_snapshot_id.to_string());
            refs.extend(value.integrated_attempt_ids.iter().map(ToString::to_string));
            refs.extend(value.revalidated_anchor_refs.iter().cloned());
            refs.extend(value.evidence_refs.iter().cloned());
        }
        JournalPayload::SegmentationCorrectionRecorded(value) => {
            refs.extend(value.predecessor_revision_id.map(|id| id.to_string()));
            refs.extend(
                value
                    .source_episode_ids
                    .iter()
                    .chain(&value.replacement_episode_ids)
                    .map(ToString::to_string),
            );
            refs.extend(value.evidence_refs.iter().cloned());
        }
        JournalPayload::SourceReceiptRecorded(value) => {
            refs.insert(value.source_observation_id.to_string());
        }
        JournalPayload::SourceObservationRecorded(value) => {
            refs.insert(value.source_receipt_ref.to_string());
        }
        JournalPayload::EvidenceSurfaceRecorded(value) => {
            refs.insert(value.source_observation_revision_ref.to_string());
        }
        JournalPayload::AtomRecorded(value) => {
            refs.extend(
                value
                    .source_observation_refs
                    .iter()
                    .map(ToString::to_string),
            );
            refs.extend(value.evidence_refs.iter().cloned());
            refs.extend(value.supports_revision_refs.iter().map(ToString::to_string));
        }
        JournalPayload::ProcedureRevisionRecorded(value) => {
            refs.extend(value.draft.evidence_refs.iter().cloned());
            refs.extend(
                value
                    .draft
                    .support_revision_refs
                    .iter()
                    .map(ToString::to_string),
            );
        }
        JournalPayload::RevisionProposalRecorded(value) => {
            refs.extend(value.evidence_refs.iter().cloned());
            refs.extend(value.source_cohort_refs.iter().cloned());
        }
        JournalPayload::CoreMembershipRecorded(value) => {
            refs.insert(value.atom_revision_id.to_string());
            refs.insert(value.support_contract_ref.to_string());
            refs.extend(
                value
                    .authorization_revision_refs
                    .iter()
                    .map(ToString::to_string),
            );
        }
        JournalPayload::GlobalSupportContractRecorded(value) => {
            refs.extend(value.support_revision_refs.iter().map(ToString::to_string));
            refs.extend(
                value
                    .authorization_revision_refs
                    .iter()
                    .map(ToString::to_string),
            );
        }
        JournalPayload::SemanticDigestRecorded(value) => {
            refs.extend(value.selected_direct_refs.iter().cloned());
        }
        JournalPayload::TaskRecorded(value) => {
            refs.extend(value.request_root_refs.iter().cloned());
        }
        JournalPayload::WorkBindingRecorded(value) => {
            refs.insert(value.operation_id.to_string());
            refs.extend(value.evidence_refs.iter().cloned());
        }
        JournalPayload::OperationBurstRecorded(value) => {
            refs.extend(
                value
                    .members
                    .iter()
                    .flat_map(|member| member.source_observation_refs.iter())
                    .map(ToString::to_string),
            );
        }
        JournalPayload::WorkEpisodeRecorded(value) => {
            refs.extend(value.operation_burst_refs.iter().map(ToString::to_string));
            refs.extend(value.semantic_digest_refs.iter().cloned());
            refs.extend(value.verification_refs.iter().cloned());
            refs.extend(value.failure_refs.iter().cloned());
            refs.extend(
                value
                    .boundary_candidate
                    .iter()
                    .flat_map(|candidate| candidate.evidence_refs.iter())
                    .map(ToString::to_string),
            );
        }
        JournalPayload::AttemptRecorded(value) => {
            refs.extend(
                value
                    .local_outcome_refs
                    .iter()
                    .chain(&value.parent_verification_refs)
                    .chain(&value.outcome_refs)
                    .chain(&value.interruption_refs)
                    .chain(&value.explicit_abandon_refs)
                    .chain(&value.supersede_evidence_refs)
                    .cloned(),
            );
        }
        JournalPayload::WorkArtifactRecorded(value) => {
            refs.extend(
                value
                    .revision
                    .source_observation_refs
                    .iter()
                    .map(ToString::to_string),
            );
        }
        _ => {}
    }
    refs
}

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
            "# EverTrace selected object\n\nFrontier: {frontier}\n\nObject: {}\n\nRevision: {}\n\nScope: {:?}\n\nLifecycle: {:?}; publication: {:?}; support: {:?}\n\nComplete stored content (selected object only):\n\n",
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
            if receipt.protected_length != bytes.len() as u64 {
                return Err(Failure::Corrupt);
            }
            if receipt.protected_presentation.as_ref().is_some_and(
                |presentation| match presentation {
                    evertrace_domain::evidence::ProtectedPresentation::Inline { text } => {
                        text.as_bytes() != bytes
                    }
                    evertrace_domain::evidence::ProtectedPresentation::Preview { text } => {
                        !bytes.starts_with(text.as_bytes())
                    }
                    evertrace_domain::evidence::ProtectedPresentation::Unavailable { .. } => false,
                },
            ) {
                return Err(Failure::Corrupt);
            }
            let other = snapshot
                .row(&format!(
                    "object:evidence:source_observation:{}",
                    receipt.source_observation_id
                ))
                .ok_or(Failure::Corrupt)?;
            let JournalPayload::SourceObservationRecorded(observation) = decode(other)? else {
                return Err(Failure::Corrupt);
            };
            let secret = receipt
                .protected_secret_digest
                .as_deref()
                .map(parse_hex)
                .transpose()?;
            if observation.source_receipt_ref != receipt.source_receipt_id
                || observation.payload_fingerprint
                    != hex(
                        &payload_fingerprint(receipt.canonicalization_revision, &bytes, secret)
                            .map_err(|_| Failure::Corrupt)?,
                    )
                || (receipt.archive_mode == SourceArchiveMode::Redacted
                    && bytes
                        .windows(b"[REDACTED]".len())
                        .filter(|span| *span == b"[REDACTED]")
                        .count()
                        < receipt.redaction_spans.len())
            {
                return Err(Failure::Corrupt);
            }
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

fn parse_hex(value: &str) -> ExportResult<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(Failure::Corrupt);
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Failure::Corrupt)?;
    }
    Ok(bytes)
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
                serde_json::to_string(&JournalPayload::TaskRecorded(Box::new(task))).unwrap(),
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
            .unwrap(),
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
        related.payload_json =
            Some(serde_json::to_string(&JournalPayload::TaskRecorded(task)).unwrap());
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
