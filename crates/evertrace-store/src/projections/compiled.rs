//! Point/window reads of published compiler output, never a rebuild or journal asset.
use super::*;

/// Published compiler records are not journal assets or independent revisions.
#[derive(Clone, Debug)]
enum CompiledProjectionData {
    Wiki(evertrace_domain::semantic::WikiProjection),
    Core(evertrace_domain::semantic::L3CoreProjection),
}
impl CompiledProjectionData {
    fn metadata(&self) -> Result<evertrace_domain::query::CompiledProjectionMetadata, StoreError> {
        use evertrace_domain::query::{
            CompiledProjectionKind as K, CompiledProjectionMetadata as M,
        };
        Ok(match self {
            Self::Wiki(v) => M {
                reference: format!("projection:wiki:{}", v.page_id),
                kind: K::Wiki,
                compiler_version: Some(v.compiler_version),
                source_watermark: v.source_watermark,
                source_count: u64::try_from(
                    v.source_atom_ids
                        .len()
                        .checked_add(v.source_episode_ids.len())
                        .ok_or(StoreError::StoreCorrupt)?,
                )
                .map_err(|_| StoreError::StoreCorrupt)?,
                render_identity: Some(v.rendered_blob_ref),
            },
            Self::Core(v) => M {
                reference: format!("projection:core:{}", v.core_projection_id),
                kind: K::Core,
                compiler_version: None,
                source_watermark: v.source_watermark,
                source_count: u64::try_from(v.active_membership_revision_ids.len())
                    .map_err(|_| StoreError::StoreCorrupt)?,
                render_identity: None,
            },
        })
    }
}

fn compiled_projection_data(row: &ObjectRow) -> Result<Option<CompiledProjectionData>, StoreError> {
    let value = match row.object_kind.as_deref() {
        Some("wiki_projection") => {
            synthesis::restore_wiki_projection(row)?.map(CompiledProjectionData::Wiki)
        }
        Some("l3_core_projection") => l3_core_projection(row)?.map(CompiledProjectionData::Core),
        _ => return Ok(None),
    };
    if let Some(value) = &value {
        let metadata = value.metadata()?;
        if row.row_kind != ObjectRowKind::Data
            || row.row_class != Some(ObjectRowClass::Projection)
            || row.current_revision_id.is_some()
            || row.object_id.is_some()
            || row.projection_generation == 0
            || row.source_event_seq != metadata.source_watermark
            || row.row_id != metadata.reference
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(value)
}

#[derive(Debug)]
pub struct CompiledDirectoryContext {
    pub frontier: u64,
    pub items: Vec<evertrace_domain::query::CompiledProjectionMetadata>,
    pub scope_available: bool,
    pub complete: bool,
    pub matching_count: Option<u64>,
    pub next_key: Option<String>,
}

#[derive(Debug)]
pub struct CompiledSourceReference {
    pub revision: RevisionId,
    pub object_kind: &'static str,
    pub membership_revision: Option<RevisionId>,
    pub contextual: bool,
}

#[derive(Debug)]
pub struct CompiledEntriesContext {
    pub frontier: u64,
    pub metadata: Option<evertrace_domain::query::CompiledProjectionMetadata>,
    pub title: Option<String>,
    pub scope_available: bool,
    pub complete: bool,
    pub matching_count: Option<u64>,
    pub sources: Vec<CompiledSourceReference>,
    pub next_offset: Option<u64>,
}

impl JournalAdmissionState {
    pub(crate) fn compiled_entries_context(
        &self,
        query: &evertrace_domain::query::CompiledProjectionQuery,
        row: Option<&ObjectRow>,
        offset: u64,
        limit: usize,
    ) -> Result<CompiledEntriesContext, StoreError> {
        use evertrace_domain::{
            query::CompiledProjectionQuery as Q,
            semantic::{AtomScope as A, CoreScopeIdentity as C},
        };
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        let Q::Entries {
            selection,
            include_global,
            reference,
        } = query
        else {
            return Err(StoreError::InvalidInput);
        };
        if !(1..=8).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let scope = self.memory_scope_context(*selection)?;
        let mut context = CompiledEntriesContext {
            frontier: self.frontier,
            metadata: None,
            title: None,
            scope_available: scope.available,
            complete: scope.available && scope.complete,
            matching_count: None,
            sources: Vec::new(),
            next_offset: None,
        };
        let Some(row) = row else {
            context.complete = false;
            return Ok(context);
        };
        if row.row_id != *reference {
            return Err(StoreError::StoreCorrupt);
        }
        let data = compiled_projection_data(row)?.ok_or(StoreError::InvalidInput)?;
        let metadata = data.metadata()?;
        if metadata.source_watermark > self.frontier {
            return Err(StoreError::StoreCorrupt);
        }
        context.metadata = Some(metadata);
        if !scope.available {
            return Ok(context);
        }
        let mut count = 0_u64;
        let mut push = |source| -> Result<(), StoreError> {
            if count >= offset && context.sources.len() < limit {
                context.sources.push(source);
            }
            count = count.checked_add(1).ok_or(StoreError::StoreCorrupt)?;
            Ok(())
        };
        match data {
            CompiledProjectionData::Wiki(v) => {
                if v.compiler_version != 1 {
                    context.complete = false;
                    return Ok(context);
                }
                let atoms = v
                    .source_atom_ids
                    .iter()
                    .map(|id| self.atoms.get(id).map(|(atom, _)| atom))
                    .collect::<Option<Vec<_>>>();
                let Some(atoms) = atoms else {
                    context.complete = false;
                    return Ok(context);
                };
                if !synthesis::wiki_render_identity(&v.topic, &atoms, &v.source_episode_ids)
                    .is_ok_and(|(identity, _)| identity == v.rendered_blob_ref)
                {
                    context.complete = false;
                    return Ok(context);
                }
                context.title = Some(v.topic);
                for atom in atoms {
                    if scope.includes(
                        *selection,
                        *include_global,
                        Some(std::slice::from_ref(&atom.scope)),
                    ) {
                        push(CompiledSourceReference {
                            revision: atom.revision_id,
                            object_kind: "atom_revision",
                            membership_revision: None,
                            contextual: false,
                        })?;
                    }
                }
                for id in v.source_episode_ids {
                    let Some((episode, seq)) = self.episodes.get(&id) else {
                        context.complete = false;
                        continue;
                    };
                    if *seq > v.source_watermark {
                        context.complete = false;
                        continue;
                    }
                    let scopes = overview::work_scopes(
                        episode.task_id,
                        episode.repository_instance_id,
                        episode.worktree_instance_id.as_slice(),
                    );
                    if scope.includes(*selection, false, Some(&scopes)) {
                        push(CompiledSourceReference {
                            revision: episode.revision_id,
                            object_kind: "work_episode",
                            membership_revision: None,
                            contextual: true,
                        })?;
                    }
                }
            }
            CompiledProjectionData::Core(v) => {
                let source_scope = match v.scope_identity {
                    C::Global => A::Global,
                    C::Repository(repository_instance_id) => A::Repository {
                        repository_instance_id,
                    },
                };
                if scope.includes(*selection, *include_global, Some(&[source_scope])) {
                    for id in v.active_membership_revision_ids {
                        let Some((member, _)) = self.scenario_core.membership_revision_entry(id)
                        else {
                            context.complete = false;
                            continue;
                        };
                        if !member.active
                            || member.scope_identity != v.scope_identity
                            || v.atom_revision_ids
                                .binary_search(&member.atom_revision_id)
                                .is_err()
                        {
                            context.complete = false;
                            continue;
                        }
                        // Membership and Atom vectors are separately sorted, never zip them.
                        push(CompiledSourceReference {
                            revision: member.atom_revision_id,
                            object_kind: "atom_revision",
                            membership_revision: Some(id),
                            contextual: false,
                        })?;
                    }
                }
            }
        }
        if offset > count {
            return Err(StoreError::InvalidInput);
        }
        if count > offset.saturating_add(context.sources.len() as u64) {
            context.next_offset = Some(offset + context.sources.len() as u64);
        }
        context.matching_count = context.complete.then_some(count);
        Ok(context)
    }

    pub(crate) fn compiled_directory_context(
        &self,
        query: &evertrace_domain::query::CompiledProjectionQuery,
        after: Option<&str>,
        limit: usize,
        mut read_page: impl FnMut(&str) -> Result<Vec<ObjectRow>, StoreError>,
    ) -> Result<CompiledDirectoryContext, StoreError> {
        use evertrace_domain::query::CompiledProjectionQuery as Q;
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        let Q::Directory {
            selection,
            include_global,
            projection,
        } = query
        else {
            return Err(StoreError::InvalidInput);
        };
        if !(1..=64).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let scope = self.memory_scope_context(*selection)?;
        let mut page = CompiledDirectoryContext {
            frontier: self.frontier,
            items: Vec::new(),
            scope_available: scope.available,
            complete: scope.available && scope.complete,
            matching_count: None,
            next_key: None,
        };
        if !scope.available {
            return Ok(page);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut scanned = after.unwrap_or("").to_owned();
        let mut ended = false;
        'scan: loop {
            let rows = read_page(&scanned)?;
            if rows.is_empty() {
                ended = true;
                break;
            }
            for row in rows {
                if std::time::Instant::now() >= deadline {
                    page.complete = false;
                    break 'scan;
                }
                if row.row_id <= scanned {
                    return Err(StoreError::StoreCorrupt);
                }
                scanned = row.row_id.clone();
                let value = compiled_projection_data(&row)?.ok_or(StoreError::StoreCorrupt)?;
                let metadata = value.metadata()?;
                if metadata.kind != *projection || metadata.source_watermark > self.frontier {
                    return Err(StoreError::StoreCorrupt);
                }
                match self.compiled_scope_includes(&value, &scope, *selection, *include_global) {
                    Some(true) => page.items.push(metadata),
                    Some(false) => {}
                    None => page.complete = false,
                }
                if page.items.len() > limit {
                    break 'scan;
                }
            }
        }
        if page.items.len() > limit {
            page.items.truncate(limit);
            page.next_key = page.items.last().map(|item| item.reference.clone());
        } else if !ended && !scanned.is_empty() {
            page.next_key = Some(scanned);
        }
        // A partial directory does not invent a scope total or reuse global stats.
        if after.is_none() && ended && page.complete {
            page.matching_count = Some(page.items.len() as u64);
        }
        Ok(page)
    }

    fn compiled_scope_includes(
        &self,
        value: &CompiledProjectionData,
        scope: &memories::MemoryScopeContext,
        selection: evertrace_domain::query::MemoryScopeSelection,
        include_global: bool,
    ) -> Option<bool> {
        use evertrace_domain::{
            query::MemoryScopeSelection as S,
            semantic::{AtomScope as A, CoreScopeIdentity as C},
        };
        if selection == S::All {
            return Some(true);
        }
        match value {
            CompiledProjectionData::Core(v) => {
                let value = match v.scope_identity {
                    C::Global => A::Global,
                    C::Repository(repository_instance_id) => A::Repository {
                        repository_instance_id,
                    },
                };
                Some(scope.includes(selection, include_global, Some(&[value])))
            }
            CompiledProjectionData::Wiki(v) => {
                let mut matches = false;
                for id in &v.source_atom_ids {
                    let (atom, _) = self.atoms.get(id)?;
                    matches |= scope.includes(
                        selection,
                        include_global,
                        Some(std::slice::from_ref(&atom.scope)),
                    );
                }
                Some(matches)
            }
        }
    }
}
