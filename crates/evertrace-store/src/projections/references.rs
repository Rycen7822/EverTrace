use super::*;

pub fn select_object_row_rows<'a>(
    rows: &'a [ObjectRow],
    identifier: &str,
) -> Result<Option<(&'a ObjectRow, bool)>, ()> {
    let eligible = |row: &&ObjectRow| {
        row.row_kind == ObjectRowKind::Data && row.row_class == Some(ObjectRowClass::Object)
    };
    let mut exact = rows
        .iter()
        .filter(eligible)
        // A checkpoint borrows its frozen Episode revision; it is not that revision's owner.
        .filter(|row| row.object_kind.as_deref() != Some("work_checkpoint"))
        .filter(|row| row.current_revision_id.as_deref() == Some(identifier));
    if let Some(row) = exact.next() {
        if exact.next().is_some() {
            return Err(());
        }
        let object_id = row.object_id.as_deref().ok_or(())?;
        let current = current_object_row_rows(rows, object_id)?.ok_or(())?;
        return Ok(Some((row, current == row)));
    }
    Ok(current_object_row_rows(rows, identifier)?.map(|row| (row, true)))
}

fn current_object_row_rows<'a>(
    rows: &'a [ObjectRow],
    object_id: &str,
) -> Result<Option<&'a ObjectRow>, ()> {
    let mut rows = rows.iter().filter(|row| {
        row.row_kind == ObjectRowKind::Data
            && row.row_class == Some(ObjectRowClass::Object)
            && row.object_id.as_deref() == Some(object_id)
    });
    let Some(mut current) = rows.next() else {
        return Ok(None);
    };
    if current.object_id.is_none() || current.current_revision_id.is_none() {
        return Err(());
    }
    let mut tied = false;
    for row in rows {
        if row.object_id.is_none() || row.current_revision_id.is_none() {
            return Err(());
        }
        match row.source_event_seq.cmp(&current.source_event_seq) {
            std::cmp::Ordering::Greater => {
                current = row;
                tied = false;
            }
            std::cmp::Ordering::Equal => tied = true,
            std::cmp::Ordering::Less => {}
        }
    }
    (!tied).then_some(Some(current)).ok_or(())
}

pub fn source_references_for(row: &ObjectRow, payload: &JournalPayload) -> BTreeSet<String> {
    let mut refs = read_dependencies_for(row, payload);
    match payload {
        JournalPayload::TaskRecorded(value) => {
            refs.extend(value.predecessor_revision_id.map(|id| id.to_string()));
            refs.extend(value.continuation_of_task_id.map(|id| id.to_string()));
            refs.extend(value.split_from_task_id.map(|id| id.to_string()));
            refs.extend(value.split_into_task_ids.iter().map(ToString::to_string));
            refs.extend(value.merged_from_task_ids.iter().map(ToString::to_string));
            refs.extend(value.merged_into_task_id.map(|id| id.to_string()));
            for scope in &value.scope_memberships {
                refs.extend(scope.repository_instance_id.map(|id| id.to_string()));
                refs.extend(scope.worktree_instance_ids.iter().map(ToString::to_string));
            }
        }
        JournalPayload::WorkstreamRecorded(value) => {
            refs.insert(value.task_id.to_string());
            refs.extend(value.predecessor_revision_id.map(|id| id.to_string()));
            refs.extend(value.repository_instance_id.map(|id| id.to_string()));
            refs.extend(value.worktree_instance_ids.iter().map(ToString::to_string));
            refs.extend(value.worktree_lineage_refs.iter().cloned());
            refs.extend(value.parent_workstream_id.map(|id| id.to_string()));
            refs.extend(
                value
                    .dependency_workstream_ids
                    .iter()
                    .map(ToString::to_string),
            );
            refs.extend(value.active_episode_id.map(|id| id.to_string()));
            refs.extend(value.execution_lane_ids.iter().map(ToString::to_string));
        }
        JournalPayload::WorkEpisodeRecorded(value) => {
            refs.insert(value.workstream_id.to_string());
            refs.extend(value.attempt_ids.iter().map(ToString::to_string));
            refs.extend(
                value
                    .competing_attempt_group_ids
                    .iter()
                    .map(ToString::to_string),
            );
            refs.extend(value.checkpoint_refs.iter().cloned());
            refs.extend(value.completed_outcome_refs.iter().cloned());
            refs.extend(value.selected_outcome_refs.iter().cloned());
            refs.extend(value.interruption_refs.iter().cloned());
        }
        JournalPayload::WorkArtifactRecorded(value) => {
            refs.extend(value.revision.parent_revision_id.map(|id| id.to_string()));
        }
        JournalPayload::ExperimentRunRecorded(value) => {
            refs.extend(value.parent_revision_id.map(|id| id.to_string()));
        }
        JournalPayload::ResultEvidenceRecorded(value) => {
            refs.extend(value.parent_revision_id.map(|id| id.to_string()));
        }
        JournalPayload::RecoveryApplicationRecorded(value) => {
            refs.extend(value.parent_revision_id.map(|id| id.to_string()));
        }
        JournalPayload::RecoveryCaptureRequestRecorded(value) => {
            refs.extend(value.parent_request_revision_id.map(|id| id.to_string()));
        }
        JournalPayload::WorktreeInstanceRecorded(value) => {
            refs.extend(
                value
                    .predecessor_revision
                    .map(|revision| format!("{}@{revision}", value.worktree_instance_id)),
            );
            refs.extend(
                value
                    .recreated_from_worktree_instance_id
                    .map(|id| id.to_string()),
            );
        }
        JournalPayload::OperationBurstRecorded(value) => {
            for member in &value.members {
                refs.insert(format!(
                    "{}@{}",
                    member.operation_id, member.operation_revision
                ));
                refs.extend(member.attempt_revision_id.map(|id| id.to_string()));
            }
        }
        JournalPayload::WorkBindingRecorded(value) => {
            refs.extend(value.predecessor_revision_id.map(|id| id.to_string()));
        }
        JournalPayload::WorktreeTransitionRecorded(value) => {
            refs.extend(
                value
                    .predecessor_revision
                    .map(|revision| format!("{}@{revision}", value.worktree_transition_id)),
            );
        }
        JournalPayload::AttemptRecorded(value) => {
            refs.insert(value.workstream_id.to_string());
            refs.extend(value.episode_id.map(|id| id.to_string()));
            refs.extend(value.resumes_from_attempt_id.map(|id| id.to_string()));
            refs.extend(
                value
                    .composed_from_attempt_ids
                    .iter()
                    .map(ToString::to_string),
            );
            refs.extend(
                value
                    .work_binding_revision_refs
                    .iter()
                    .map(ToString::to_string),
            );
        }
        _ => {}
    }
    refs
}

#[derive(Debug)]
pub struct ReferenceReadContext {
    pub source: StoredFieldsContext,
    pub page: evertrace_domain::query::ReferenceMetadataPage,
    pub targets: Vec<Option<StoredFieldsContext>>,
}

impl JournalAdmissionState {
    pub(crate) fn reference_metadata_context(
        &self,
        reference: &evertrace_domain::query::ExactRecordRef,
        after: Option<&str>,
        limit: u16,
        source: StoredFieldsContext,
        mut budget: ReadDependencyBudget,
        retained: &[ObjectRow],
        checkpoint_tools: &[RevisionId],
        cancelled: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
    ) -> Result<evertrace_domain::query::MetadataReadOutcome<ReferenceReadContext>, StoreError>
    {
        use evertrace_domain::query::{
            ExactFieldIdentity, HumanContentState as S, MetadataReadOutcome as O,
            ReferenceMetadataPage, ReferenceMetadataRecord,
        };
        let state = source.state.clone();
        let mut page = ReferenceMetadataPage {
            selection: None,
            content_state: S::Missing,
            records: Vec::new(),
            matching_count: None,
            next: None,
        };
        let Some(root) = source.selected.as_ref() else {
            return Ok(O::Page(Box::new(ReferenceReadContext {
                source,
                page,
                targets: Vec::new(),
            })));
        };
        if root.row_id != reference.stable_key
            && root.object_id.as_deref() != Some(reference.stable_key.as_str())
            && root.current_revision_id.as_deref() != Some(reference.stable_key.as_str())
        {
            return Ok(O::Page(Box::new(ReferenceReadContext {
                source,
                page,
                targets: Vec::new(),
            })));
        }
        page.selection = match (
            &root.object_id,
            &root.current_revision_id,
            &root.object_kind,
        ) {
            (Some(object), Some(revision), Some(kind)) => Some(ExactFieldIdentity {
                object_ref: object.clone(),
                revision_ref: revision.clone(),
                object_kind: kind.clone(),
                source_event_seq: root.source_event_seq,
            }),
            _ => return Err(StoreError::StoreCorrupt),
        };
        if !matches!(
            root.object_kind.as_deref(),
            Some(
                "atom_revision"
                    | "procedure_revision"
                    | "core_membership"
                    | "semantic_digest"
                    | "revision_proposal_revision"
                    | "source_receipt"
                    | "source_observation"
                    | "work_episode"
                    | "work_checkpoint"
                    | "attempt"
                    | "competing_attempt_group"
                    | "operation_burst"
                    | "operation"
                    | "host_occurrence"
                    | "scope_effect"
                    | "worktree"
                    | "worktree_snapshot"
                    | "worktree_transition"
                    | "integration_event"
                    | "work_binding"
                    | "recovery_capture_request"
                    | "recovery_bundle"
                    | "recovery_application_revision"
                    | "work_artifact"
                    | "experiment_run"
                    | "result_evidence"
                    | "procedure_usage_revision"
                    | "procedure_negative_evidence"
                    | "procedure_negative_review"
                    | "procedure_context_effect"
                    | "global_support_contract"
                    | "global_support_validation"
                    | "task"
                    | "workstream"
            )
        ) {
            page.clear(S::Unsupported);
            return Ok(O::Page(Box::new(ReferenceReadContext {
                source,
                page,
                targets: Vec::new(),
            })));
        }
        let json = root
            .payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?;
        let (payload, mut refs) = if root.object_kind.as_deref() == Some("procedure_context_effect")
        {
            let value: evertrace_domain::procedure::ProcedureContextEffectProjection =
                serde_json::from_str(json).map_err(|_| StoreError::StoreCorrupt)?;
            value.validate().map_err(|_| StoreError::StoreCorrupt)?;
            (None, procedure_effect::read_references(&value))
        } else {
            let value: JournalPayload =
                serde_json::from_str(json).map_err(|_| StoreError::StoreCorrupt)?;
            let refs = source_references_for(root, &value);
            (Some(value), refs)
        };
        if let Some(JournalPayload::WorkCheckpointRecorded(checkpoint)) = payload.as_ref() {
            use evertrace_domain::work::{ArtifactActor, WorkArtifactKind};
            for revision in checkpoint_tools {
                let (artifact, seq) = self
                    .artifact_revisions
                    .get(revision)
                    .ok_or(StoreError::StoreCorrupt)?;
                if *seq > state.frontier
                    || artifact.revision.kind != WorkArtifactKind::Log
                    || artifact.revision.produced_by_refs
                        != [ArtifactActor::WorkEpisode(checkpoint.episode_id)]
                {
                    return Err(StoreError::StoreCorrupt);
                }
                refs.insert(revision.to_string());
            }
        }
        refs.extend(
            retained
                .iter()
                .filter(|row| row.object_kind.as_deref() == Some("procedure_context_effect"))
                .map(|row| row.row_id.clone()),
        );
        let contracts: Box<dyn Iterator<Item = RevisionId> + '_> = match payload.as_ref() {
            Some(JournalPayload::AtomRecorded(atom)) => Box::new(
                self.scenario_core
                    .atom_support_contract_refs(atom.revision_id)
                    .into_iter(),
            ),
            Some(JournalPayload::ProcedureRevisionRecorded(procedure)) => Box::new(
                self.scenario_core
                    .successor_support_contract_refs(procedure.revision_id),
            ),
            _ => Box::new(std::iter::empty()),
        };
        for contract in contracts {
            if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(StoreError::Io);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
            refs.insert(contract.to_string());
            if refs.len() > READ_DEPENDENCY_LIMIT {
                return Ok(O::TooLarge);
            }
        }
        if let Some(JournalPayload::GlobalSupportContractRecorded(contract)) = payload.as_ref()
            && let Some(validation) = self
                .scenario_core
                .current_validation(contract.support_contract_revision_id)
        {
            refs.insert(validation.validation_revision_id.to_string());
        }
        if let Some(JournalPayload::OperationDerived(operation)) = payload.as_ref() {
            // All recorded binding revisions, not a heuristic current owner or extra physical execution.
            for (binding, _) in self.work_bindings.values() {
                if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StoreError::Io);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(O::TooLarge);
                }
                if binding.operation_id == operation.operation_id {
                    refs.insert(binding.work_binding_revision_id.to_string());
                    if refs.len() > READ_DEPENDENCY_LIMIT {
                        return Ok(O::TooLarge);
                    }
                }
            }
        }
        if let Some(JournalPayload::WorktreeInstanceRecorded(tree)) = payload.as_ref() {
            for (transition, _) in self.worktree_transitions.values() {
                if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StoreError::Io);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(O::TooLarge);
                }
                if transition.from_worktree_instance_id == tree.worktree_instance_id
                    || transition.to_worktree_instance_id == tree.worktree_instance_id
                {
                    refs.insert(format!(
                        "{}@{}",
                        transition.worktree_transition_id, transition.transition_revision
                    ));
                    if refs.len() > READ_DEPENDENCY_LIMIT {
                        return Ok(O::TooLarge);
                    }
                }
            }
            for (integration, _) in self.integration_events.values() {
                if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StoreError::Io);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(O::TooLarge);
                }
                if integration.source_worktree_instance_id == tree.worktree_instance_id
                    || integration.destination_worktree_instance_id == tree.worktree_instance_id
                {
                    refs.insert(integration.integration_event_id.to_string());
                    if refs.len() > READ_DEPENDENCY_LIMIT {
                        return Ok(O::TooLarge);
                    }
                }
            }
        }
        if let Some(JournalPayload::WorkEpisodeRecorded(episode)) = payload.as_ref() {
            use evertrace_domain::work::{ArtifactActor, ArtifactScope, WorkArtifactKind};
            let revision = episode.revision_id.to_string();
            for job in self.jobs.values() {
                if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StoreError::Io);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(O::TooLarge);
                }
                if job.kind != crate::PHASE_REFINEMENT_JOB_KIND
                    || job.state != crate::JobStatus::Succeeded
                    || job.target_revision != revision
                    || job.target_watermark != episode.source_watermark
                    || job.target_generation != episode.revision_generation
                {
                    continue;
                }
                let Some(artifact_revision) = job.terminal.as_ref().and_then(|terminal| {
                    terminal.result_ref.as_deref()?.parse::<RevisionId>().ok()
                }) else {
                    continue;
                };
                let Some((artifact, _)) = self.artifact_revisions.get(&artifact_revision) else {
                    continue;
                };
                let scope_matches = match artifact.revision.scope {
                    ArtifactScope::Task { task_id } => {
                        episode.repository_instance_id.is_none()
                            && episode.worktree_instance_id.is_none()
                            && episode.task_id == task_id
                    }
                    ArtifactScope::Worktree {
                        repository_instance_id,
                        worktree_instance_id,
                    } => {
                        episode.repository_instance_id == Some(repository_instance_id)
                            && episode.worktree_instance_id == Some(worktree_instance_id)
                    }
                    _ => false,
                };
                // The successful job pins the exact reviewed input and output. Neither current artifact
                // heads nor later advice about another revision belong to this historical selection.
                if scope_matches
                    && artifact.revision.kind == WorkArtifactKind::Review
                    && artifact.revision.produced_by_refs
                        == [ArtifactActor::WorkEpisode(episode.episode_id)]
                {
                    refs.insert(artifact_revision.to_string());
                    if refs.len() > READ_DEPENDENCY_LIMIT {
                        return Ok(O::TooLarge);
                    }
                }
            }
        }
        if let Some(JournalPayload::ExperimentRunRecorded(run)) = payload.as_ref() {
            let view = self.controlled_run_admission();
            if let Some(parent) =
                super::autoresearch::native_retry_parent(&view, run, cancelled, deadline)?
            {
                refs.insert(parent.to_string());
            }
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
        }
        // Current child revisions by canonical ownership/pinned input, not a reconstruction of a past subtree.
        let children: Box<dyn Iterator<Item = (bool, RevisionId)> + '_> = match payload.as_ref() {
            Some(JournalPayload::TaskRecorded(task)) => Box::new(
                self.workstreams
                    .values()
                    .map(|(stream, _)| (stream.task_id == task.task_id, stream.revision_id)),
            ),
            Some(JournalPayload::WorkstreamRecorded(stream)) => Box::new(
                self.episodes
                    .values()
                    .map(|(episode, _)| {
                        (
                            episode.workstream_id == stream.workstream_id,
                            episode.revision_id,
                        )
                    })
                    .chain(self.experiment_runs.values().map(|(run, _)| {
                        (run.workstream_id == stream.workstream_id, run.revision_id)
                    })),
            ),
            Some(JournalPayload::AttemptRecorded(attempt)) => {
                Box::new(self.experiment_runs.values().map(|(run, _)| {
                    (
                        run.attempt_binding_status
                            == evertrace_domain::work::AttemptBindingStatus::Resolved
                            && run.attempt_id == Some(attempt.attempt_id)
                            && run.workstream_id == attempt.workstream_id,
                        run.revision_id,
                    )
                }))
            }
            Some(JournalPayload::RecoveryBundleRecorded(bundle)) => {
                Box::new(self.recovery_applications.values().map(|(application, _)| {
                    (
                        application.recovery_bundle_id == bundle.recovery_bundle_id,
                        application.revision_id,
                    )
                }))
            }
            Some(JournalPayload::ExperimentRunRecorded(run)) => {
                Box::new(self.result_evidence.values().map(|(result, _)| {
                    (
                        result.experiment_run_id == run.run_id
                            && result.experiment_run_revision_id == run.revision_id,
                        result.revision_id,
                    )
                }))
            }
            _ => Box::new(std::iter::empty()),
        };
        for (belongs, revision) in children {
            if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(StoreError::Io);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
            if belongs {
                refs.insert(revision.to_string());
                if refs.len() > READ_DEPENDENCY_LIMIT {
                    return Ok(O::TooLarge);
                }
            }
        }
        let source_tuple = match payload.as_ref() {
            Some(JournalPayload::SourceReceiptRecorded(value)) => {
                Some((&value.source_instance_id, &value.source_revision))
            }
            Some(JournalPayload::SourceObservationRecorded(value)) => {
                Some((&value.source_instance_id, &value.source_revision))
            }
            _ => None,
        };
        if let Some((instance, revision)) = source_tuple {
            let source_revision = source_revision_ref(instance, revision);
            // This is source-revision membership, not proof that this record belongs to or is covered by the lane.
            for (capture, _) in self.capture_receipts.values() {
                if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StoreError::Io);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(O::TooLarge);
                }
                if capture.source_revision_refs.contains(&source_revision) {
                    refs.insert(capture.capture_receipt_revision_id.to_string());
                    if refs.len() > READ_DEPENDENCY_LIMIT {
                        return Ok(O::TooLarge);
                    }
                }
            }
        }
        refs.remove(&root.row_id);
        // These immutable events share their stream's parent ID; it is a true parent link, not a self alias.
        if !matches!(
            root.object_kind.as_deref(),
            Some("global_support_validation" | "procedure_negative_review")
        ) && let Some(value) = &root.object_id
        {
            refs.remove(value);
        }
        // A context projection's revision column is its Procedure input, not its own immutable revision.
        if root.object_kind.as_deref() != Some("procedure_context_effect")
            && let Some(value) = &root.current_revision_id
        {
            refs.remove(value);
        }
        if refs.len() > READ_DEPENDENCY_LIMIT {
            return Ok(O::TooLarge);
        }
        let mut records = BTreeMap::<String, ReferenceMetadataRecord>::new();
        for reference in refs {
            if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(StoreError::Io);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
            // A dependency subset may contain an old revision; resolve logical current from the canonical lookup.
            let mut candidates =
                self.capture_product_rows(self.stored_reference_rows(&reference)?)?;
            if candidates.is_empty()
                && let Some(row) = retained.iter().find(|row| {
                    row.row_id == reference
                        || row.current_revision_id.as_deref() == Some(reference.as_str())
                })
            {
                candidates.push(row.clone());
            }
            for row in &candidates {
                budget.rows += 1;
                budget.bytes += row.payload_json.as_ref().map_or(0, |value| value.len()) as u64;
            }
            if budget.rows > READ_DEPENDENCY_LIMIT || budget.bytes > READ_DEPENDENCY_BYTES {
                return Ok(O::TooLarge);
            }
            candidates.retain(|row| {
                row.row_id == reference
                    || row.object_id.as_deref() == Some(reference.as_str())
                    || row.current_revision_id.as_deref() == Some(reference.as_str())
            });
            if candidates
                .iter()
                .any(|row| row.row_class == Some(ObjectRowClass::Object))
            {
                candidates.retain(|row| row.row_class == Some(ObjectRowClass::Object));
            }
            let selected = if candidates.len() == 1 {
                Ok(Some(&candidates[0]))
            } else {
                select_object_row_rows(&candidates, &reference)
                    .map(|value| value.map(|value| value.0))
            };
            let (key, status, metadata) = match selected {
                Ok(Some(row)) => (
                    row.row_id.clone(),
                    S::Ready,
                    Some(crate::JournalWriter::metadata_record(row, None)),
                ),
                Ok(None) => (reference.clone(), S::Missing, None),
                Err(()) => (reference.clone(), S::Unavailable, None),
            };
            records
                .entry(key.clone())
                .or_insert_with(|| ReferenceMetadataRecord {
                    stable_key: key,
                    references: Vec::new(),
                    content_state: status,
                    metadata,
                })
                .references
                .push(reference);
        }
        if after.is_some_and(|key| !records.contains_key(key)) {
            return Err(StoreError::InvalidInput);
        }
        page.content_state = S::Ready;
        page.matching_count = Some(records.len() as u64);
        page.records = records
            .into_values()
            .filter(|record| after.is_none_or(|key| record.stable_key.as_str() > key))
            .take(usize::from(limit) + 1)
            .collect();
        if page.records.len() > usize::from(limit) {
            page.records.truncate(usize::from(limit));
            page.next = page.records.last().map(|record| record.stable_key.clone());
        }
        let mut targets = Vec::with_capacity(page.records.len());
        for record in &mut page.records {
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
            if record.metadata.is_none() {
                targets.push(None);
                continue;
            }
            let revision = record
                .metadata
                .as_ref()
                .and_then(|value| value.get("current_revision_id"))
                .and_then(serde_json::Value::as_str);
            let matches = |row: &&ObjectRow| {
                row.row_id == record.stable_key && row.current_revision_id.as_deref() == revision
            };
            let selected = source
                .rows
                .iter()
                .find(matches)
                .or_else(|| retained.iter().find(matches))
                .cloned();
            let selected = match selected {
                Some(row) => Some(row),
                None => self
                    .capture_product_rows(self.stored_reference_rows(&record.references[0])?)?
                    .into_iter()
                    .find(|row| {
                        row.row_id == record.stable_key
                            && row.current_revision_id.as_deref() == revision
                    }),
            };
            let context = match self.stored_fields_context_for_row(
                selected,
                state.clone(),
                cancelled,
                deadline,
                &mut budget,
            )? {
                O::Page(value) => *value,
                O::TooLarge => return Ok(O::TooLarge),
                O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
            };
            if !context.rows.iter().any(|row| {
                row.row_id == record.stable_key && row.current_revision_id.as_deref() == revision
            }) {
                record.content_state = S::Missing;
                record.metadata = None;
                targets.push(None);
            } else {
                targets.push(Some(context));
            }
        }
        Ok(O::Page(Box::new(ReferenceReadContext {
            source,
            page,
            targets,
        })))
    }
}
