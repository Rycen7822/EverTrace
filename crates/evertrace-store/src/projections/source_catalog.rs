//! Bounded facts of the committed source catalogue, never host discovery or body parsing.
use super::*;
use evertrace_domain::{
    query::{ExactRecordRef, HumanContentState as State, MemoryScopeSelection as Selection},
    source::{
        SourceCatalogEntry, SourceCatalogQuery, SourceMetadataPage, SourceSelectionBasis as Basis,
    },
};

impl JournalAdmissionState {
    /// Archive visibility depends on the owning canonical catalogue fact, not a human page or current job.
    pub(super) fn source_catalog_contains(&self, source: &str) -> Result<bool, StoreError> {
        for current in self.session_imports.values() {
            if current.source_instance() == source && self.source_catalog_visible(current)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn source_catalog_visible(
        &self,
        current: &crate::SessionImportCurrent,
    ) -> Result<bool, StoreError> {
        Ok(!filter_product_rows(
            vec![crate::session_import::current_row(
                current,
                PROJECTION_GENERATION,
            )?],
            &self.deletions,
            &self.scope_purges,
            self.repository_closures.values(),
        )?
        .is_empty())
    }

    fn source_origin_scope(
        &self,
        current: &crate::SessionImportCurrent,
    ) -> Result<Option<(RepositoryId, WorktreeId)>, StoreError> {
        let Some(origin) = &current.metadata.prospective_origin else {
            return Ok(None);
        };
        let snapshot = &self
            .worktree_snapshots
            .get(&origin.snapshot_ref)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let tree = &self
            .worktrees
            .get(&snapshot.worktree_instance_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        Ok(Some((
            tree.repository_instance_id,
            tree.worktree_instance_id,
        )))
    }

    fn source_selection(
        &self,
        selection: Selection,
    ) -> Result<(State, Option<ExactRecordRef>), StoreError> {
        let fact = match selection {
            Selection::Repository { repository_id } => {
                self.repositories.get(&repository_id).map(|(value, seq)| {
                    (
                        JournalPayload::RepositoryInstanceRecorded(Box::new(value.clone())),
                        *seq,
                    )
                })
            }
            Selection::Worktree { worktree_id } => {
                self.worktrees.get(&worktree_id).map(|(value, seq)| {
                    (
                        JournalPayload::WorktreeInstanceRecorded(Box::new(value.clone())),
                        *seq,
                    )
                })
            }
            Selection::Task { task_id } => self
                .tasks
                .get(&task_id)
                .map(|(value, seq)| (JournalPayload::TaskRecorded(Box::new(value.clone())), *seq)),
            _ => return Ok((State::Ready, None)),
        };
        let Some((fact, seq)) = fact else {
            return Ok((State::Missing, None));
        };
        if !self.scope_fact_visible(&fact, seq)? {
            return Ok((State::Missing, None));
        }
        let reference = if let JournalPayload::TaskRecorded(task) = fact {
            Some(ExactRecordRef {
                stable_key: task.task_id.to_string(),
                revision_ref: Some(task.revision_id.to_string()),
            })
        } else {
            None
        };
        Ok((State::Ready, reference))
    }

    fn source_catalog_basis(
        &self,
        current: &crate::SessionImportCurrent,
        selection: Selection,
        task_sources: &BTreeSet<String>,
    ) -> Result<Option<Basis>, StoreError> {
        let metadata = &current.metadata;
        let origin = self.source_origin_scope(current)?;
        Ok(match selection {
            Selection::All => Some(Basis::Catalogue),
            Selection::Global => None, // Sources are provenance, never global reusable assets.
            Selection::Unassigned
                if metadata.resolved_repository_instance_id.is_none()
                    && metadata.resolved_worktree_instance_id.is_none()
                    && origin.is_none() =>
            {
                Some(Basis::Unassigned)
            }
            Selection::Repository { repository_id }
                if metadata.resolved_repository_instance_id == Some(repository_id) =>
            {
                Some(Basis::HistoricalMetadata)
            }
            Selection::Worktree { worktree_id }
                if metadata.resolved_worktree_instance_id == Some(worktree_id) =>
            {
                Some(Basis::HistoricalMetadata)
            }
            Selection::Repository { repository_id }
                if origin.is_some_and(|scope| scope.0 == repository_id) =>
            {
                Some(Basis::ProspectiveOrigin)
            }
            Selection::Worktree { worktree_id }
                if origin.is_some_and(|scope| scope.1 == worktree_id) =>
            {
                Some(Basis::ProspectiveOrigin)
            }
            Selection::Task { .. } if task_sources.contains(&current.source_instance()) => {
                Some(Basis::TaskRequest)
            }
            _ => None,
        })
    }

    fn source_metadata_record(
        &self,
        key: &str,
        current: &crate::SessionImportCurrent,
        selection_basis: Basis,
    ) -> Result<SourceCatalogEntry, StoreError> {
        let job = match self.import_jobs.get(key) {
            Some(ids) if ids.len() > 1 => return Err(StoreError::StoreCorrupt),
            Some(ids) => ids
                .first()
                .map(|id| self.jobs.get(id).ok_or(StoreError::StoreCorrupt))
                .transpose()?,
            None => None,
        };
        let instance = current.source_instance();
        let watermark = self
            .source_watermarks
            .get(&instance)
            .and_then(|state| state.revisions.get(&current.metadata.source_revision));
        let metadata = &current.metadata;
        let origin = metadata.prospective_origin.as_ref();
        let origin_scope = self.source_origin_scope(current)?;
        let entry = SourceCatalogEntry {
            key: key.to_owned(),
            session_id: current.session_id.clone(),
            source_instance_id: instance,
            catalog_revision: current.revision,
            source_revision: metadata.source_revision.clone(),
            metadata_state: metadata.metadata_state,
            body_state: current.body_state,
            access_decision: current.access_decision,
            workspace_resolution_kind: metadata.workspace_resolution_kind,
            resolved_repository_id: metadata.resolved_repository_instance_id,
            resolved_worktree_id: metadata.resolved_worktree_instance_id,
            prospective_repository_id: origin_scope.map(|scope| scope.0),
            prospective_worktree_id: origin_scope.map(|scope| scope.1),
            selection_basis,
            repository_read_restrictions: metadata.repository_read_restrictions.clone(),
            workspace_hint: metadata.workspace_hint.clone(),
            source_format: metadata.source_format.clone(),
            started_at_us: metadata.started_at_us,
            ended_at_us: metadata.ended_at_us,
            file_size: metadata.file_size,
            observed_end: origin.map(|v| v.observed_end),
            record_start: origin.and_then(|v| v.record_start),
            origin_closed: origin.map(|v| v.closed),
            archived_through: watermark.map(|v| v.source_sequence),
            earlier_through: watermark
                .and_then(|v| v.earlier_prefix.as_ref().map(|p| p.through_byte)),
            job_id: job.map(|v| v.job_id),
            job_state: job.map(|v| format!("{:?}", v.state)),
        };
        if !entry.validate() {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(entry)
    }

    pub(crate) fn source_metadata(
        &self,
        query: &SourceCatalogQuery,
        after: Option<&str>,
        limit: u16,
        cancelled: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
    ) -> Result<evertrace_domain::query::MetadataReadOutcome<SourceMetadataPage>, StoreError> {
        use evertrace_domain::query::MetadataReadOutcome as O;
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if !(1..=64).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let check = || -> Result<bool, StoreError> {
            if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(StoreError::Io);
            }
            Ok(std::time::Instant::now() < deadline)
        };
        let (state, selection_ref) = self.source_selection(query.selection)?;
        let mut page = SourceMetadataPage {
            query: query.clone(),
            records: Vec::new(),
            state,
            selection_ref,
            matching_count: None,
            next: None,
        };
        if page.state != State::Ready {
            return Ok(O::Page(Box::new(page)));
        }
        let mut task_sources = BTreeSet::new();
        let mut related = BTreeSet::new();
        if let Selection::Task { task_id } = query.selection {
            let mut bytes = 0;
            for reference in &self
                .tasks
                .get(&task_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .request_root_refs
            {
                if !check()? {
                    return Ok(O::TooLarge);
                }
                let Some((row, id)) = self.directory_source_root(reference)? else {
                    page.clear(State::Unavailable);
                    return Ok(O::Page(Box::new(page)));
                };
                bytes += row.payload_json.as_ref().map_or(0, |value| value.len()) as u64;
                if bytes > READ_DEPENDENCY_BYTES {
                    return Ok(O::TooLarge);
                }
                let observation = &self
                    .source_observations
                    .get(&id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                task_sources.insert(observation.source_instance_id.as_str().to_owned());
            }
        }
        let catalogue_matches = |current: &crate::SessionImportCurrent| {
            query
                .session_id
                .as_ref()
                .is_none_or(|id| id == &current.session_id)
                && query
                    .source_instance_id
                    .as_ref()
                    .is_none_or(|id| id == &current.source_instance())
                && (!query.unassigned_only
                    || (current.metadata.resolved_repository_instance_id.is_none()
                        && current.metadata.resolved_worktree_instance_id.is_none()))
        };
        // Only candidate catalogue sources need retained-scope proof. Reuse the source range index;
        // unrelated Hook/other evidence and protected presentations are never walked.
        if !matches!(query.selection, Selection::All | Selection::Global) {
            for current in self.session_imports.values() {
                if !check()? {
                    return Ok(O::TooLarge);
                }
                if !catalogue_matches(current) {
                    continue;
                }
                let direct = self.source_catalog_basis(current, query.selection, &task_sources)?;
                let unassigned = query.selection == Selection::Unassigned;
                if (unassigned && direct.is_none()) || (!unassigned && direct.is_some()) {
                    continue;
                }
                let source = current.source_instance();
                let prefix = format!("{source}@");
                'source_records: for (_, ranges) in self
                    .source_ranges
                    .range(prefix.clone()..)
                    .take_while(|(key, _)| key.starts_with(&prefix))
                {
                    for id in ranges.receipt_ids.values().flatten() {
                        if !check()? {
                            return Ok(O::TooLarge);
                        }
                        let receipt = &self
                            .source_receipts
                            .get(id)
                            .ok_or(StoreError::StoreCorrupt)?
                            .0;
                        if receipt.source_instance_id.as_str() != source {
                            continue;
                        }
                        let matches = match query.selection {
                            Selection::Task { task_id } => receipt.task_id == Some(task_id),
                            Selection::Repository { repository_id } => {
                                receipt.repository_instance_id == Some(repository_id)
                            }
                            Selection::Worktree { worktree_id } => {
                                receipt.worktree_instance_id == Some(worktree_id)
                            }
                            Selection::Unassigned => {
                                receipt.repository_instance_id.is_some()
                                    || receipt.worktree_instance_id.is_some()
                            }
                            _ => false,
                        };
                        if !matches {
                            continue;
                        }
                        let (observation, seq) = self
                            .source_observations
                            .get(&receipt.source_observation_id)
                            .ok_or(StoreError::StoreCorrupt)?;
                        if !self
                            .capture_product_rows(vec![source_observation_row(observation, *seq)?])?
                            .is_empty()
                        {
                            related.insert(source.clone());
                            if related.len() > READ_DEPENDENCY_LIMIT {
                                return Ok(O::TooLarge);
                            }
                            break 'source_records;
                        }
                    }
                }
            }
        }
        let matches = |current: &crate::SessionImportCurrent| -> Result<Option<Basis>, StoreError> {
            if !catalogue_matches(current) {
                return Ok(None);
            }
            let direct = self.source_catalog_basis(current, query.selection, &task_sources)?;
            let retained = related.contains(&current.source_instance());
            Ok(if query.selection == Selection::Unassigned {
                if retained { None } else { direct }
            } else {
                direct.or_else(|| retained.then_some(Basis::RetainedRecord))
            })
        };
        if let Some(key) = after {
            let current = self
                .session_imports
                .get(key)
                .ok_or(StoreError::InvalidInput)?;
            if matches(current)?.is_none() || !self.source_catalog_visible(current)? {
                return Err(StoreError::InvalidInput);
            }
        }
        let mut selected = Vec::with_capacity(usize::from(limit) + 1);
        let mut matching_count = 0_u64;
        for (key, current) in &self.session_imports {
            if !check()? {
                return Ok(O::TooLarge);
            }
            let Some(basis) = matches(current)? else {
                continue;
            };
            if !self.source_catalog_visible(current)? {
                continue;
            }
            matching_count = matching_count
                .checked_add(1)
                .ok_or(StoreError::StoreCorrupt)?;
            if after.is_none_or(|after| key.as_str() > after)
                && selected.len() <= usize::from(limit)
            {
                selected.push((key, current, basis));
            }
        }
        if selected.len() > usize::from(limit) {
            selected.truncate(usize::from(limit));
            page.next = selected.last().map(|(key, _, _)| (*key).clone());
        }
        for (key, current, basis) in selected {
            if !check()? {
                return Ok(O::TooLarge);
            }
            page.records
                .push(self.source_metadata_record(key, current, basis)?);
        }
        page.matching_count = Some(matching_count);
        Ok(O::Page(Box::new(page)))
    }
}
