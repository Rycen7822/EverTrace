//! Bounded facts of the committed source catalogue, never host discovery or body parsing.
use super::*;
use evertrace_domain::source::{
    SourceCatalogCursor, SourceCatalogEntry, SourceCatalogPage, SourceCatalogQuery,
};

impl JournalAdmissionState {
    pub(crate) fn source_catalog_page(
        &self,
        query: &SourceCatalogQuery,
        after: Option<&SourceCatalogCursor>,
        limit: usize,
    ) -> Result<SourceCatalogPage, StoreError> {
        use std::ops::Bound::{Excluded, Unbounded};
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if !(1..=64).contains(&limit) || after.is_some_and(|v| v.validate_for(query).is_err()) {
            return Err(StoreError::InvalidInput);
        }
        let matches = |current: &crate::SessionImportCurrent| {
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
        let visible = |current: &crate::SessionImportCurrent| self.source_catalog_visible(current);
        if let Some(cursor) = after
            && cursor.frontier == self.frontier
        {
            let current = self
                .session_imports
                .get(&cursor.after_source)
                .ok_or(StoreError::InvalidInput)?;
            if !matches(current) || !visible(current)? {
                return Err(StoreError::InvalidInput);
            }
        }
        let mut entries = Vec::with_capacity(limit);
        let mut next_cursor = None;
        let bound = after.map_or(Unbounded, |cursor| Excluded(cursor.after_source.clone()));
        for (key, current) in self.session_imports.range((bound, Unbounded)) {
            if !matches(current) || !visible(current)? {
                continue;
            }
            if entries.len() == limit {
                next_cursor = Some(
                    serde_json::to_string(&SourceCatalogCursor {
                        frontier: self.frontier,
                        query: query.clone(),
                        after_source: entries
                            .last()
                            .map(|entry: &SourceCatalogEntry| entry.key.clone())
                            .ok_or(StoreError::StoreCorrupt)?,
                    })
                    .map_err(|_| StoreError::StoreCorrupt)?,
                );
                break;
            }
            entries.push(self.source_metadata_record(key, current)?);
        }
        Ok(SourceCatalogPage {
            frontier: self.frontier,
            query: query.clone(),
            entries,
            next_cursor,
        })
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

    fn source_metadata_record(
        &self,
        key: &str,
        current: &crate::SessionImportCurrent,
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
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::source::SourceMetadataPage>,
        StoreError,
    > {
        use evertrace_domain::{query::MetadataReadOutcome as O, source::SourceMetadataPage};
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if !(1..=64).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let matches = |current: &crate::SessionImportCurrent| {
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
        if let Some(key) = after {
            let current = self
                .session_imports
                .get(key)
                .ok_or(StoreError::InvalidInput)?;
            if !matches(current) || !self.source_catalog_visible(current)? {
                return Err(StoreError::InvalidInput);
            }
        }
        let mut selected = Vec::with_capacity(usize::from(limit) + 1);
        let mut matching_count = 0_u64;
        for (key, current) in &self.session_imports {
            if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(StoreError::Io);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
            if !matches(current) || !self.source_catalog_visible(current)? {
                continue;
            }
            matching_count = matching_count
                .checked_add(1)
                .ok_or(StoreError::StoreCorrupt)?;
            if after.is_none_or(|after| key.as_str() > after)
                && selected.len() <= usize::from(limit)
            {
                selected.push((key, current));
            }
        }
        let next = (selected.len() > usize::from(limit))
            .then(|| selected[usize::from(limit) - 1].0.clone());
        selected.truncate(usize::from(limit));
        let mut records = Vec::with_capacity(selected.len());
        for (key, current) in selected {
            if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(StoreError::Io);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
            records.push(self.source_metadata_record(key, current)?);
        }
        Ok(O::Page(Box::new(SourceMetadataPage {
            query: query.clone(),
            records,
            matching_count,
            next,
        })))
    }
}
