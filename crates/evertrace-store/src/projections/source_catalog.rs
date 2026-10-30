//! Human reads of the already committed source catalogue, never host discovery.
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
        let visible = |current: &crate::SessionImportCurrent| -> Result<bool, StoreError> {
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
        };
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
                key: key.clone(),
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
            entries.push(entry);
        }
        Ok(SourceCatalogPage {
            frontier: self.frontier,
            query: query.clone(),
            entries,
            next_cursor,
        })
    }
}
