//! Request-local human metadata browsing over the canonical admission indexes.
use super::*;
use evertrace_domain::query::{
    MemoryBrowseCursor, MemoryBrowseOrder, MemoryBrowseQuery, MemoryReadingKind,
};

#[derive(Debug)]
pub struct MemoryBrowseContext {
    pub page: MemoriesCurrentContext,
    /// Current metadata records; body access remains an independent decision.
    pub total_count: Option<u64>,
    pub matching_count: Option<u64>,
    pub scope_available: bool,
    pub counts_complete: bool,
    pub unresolved_scope_count: u64,
}

impl JournalAdmissionState {
    /// Directory identities only. Semantic memories are never serialized here.
    pub(crate) fn scope_directory_context(
        &self,
        query: &evertrace_domain::query::ScopeDirectoryQuery,
        after: Option<&str>,
        limit: usize,
        deadline: std::time::Instant,
    ) -> Result<ScopeDirectoryReadContext, StoreError> {
        use evertrace_domain::query::ScopeBoundary;
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if !(1..=64).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let parent_available = match query.parent {
            None => true,
            Some(ScopeBoundary::Repository { repository_id }) => self
                .repositories
                .get(&repository_id)
                .map(|(v, seq)| {
                    self.scope_fact_visible(
                        &JournalPayload::RepositoryInstanceRecorded(Box::new(v.clone())),
                        *seq,
                    )
                })
                .transpose()?
                .unwrap_or(false),
            Some(ScopeBoundary::Worktree { worktree_id }) => self
                .worktrees
                .get(&worktree_id)
                .map(|(v, seq)| {
                    self.scope_fact_visible(
                        &JournalPayload::WorktreeInstanceRecorded(Box::new(v.clone())),
                        *seq,
                    )
                })
                .transpose()?
                .unwrap_or(false),
            Some(ScopeBoundary::Task { task_id }) => self
                .tasks
                .get(&task_id)
                .map(|(v, seq)| {
                    self.scope_fact_visible(
                        &JournalPayload::TaskRecorded(Box::new(v.clone())),
                        *seq,
                    )
                })
                .transpose()?
                .unwrap_or(false),
        };
        let mut context = ScopeDirectoryReadContext {
            frontier: self.frontier,
            parent_available,
            complete: parent_available,
            items: Vec::new(),
            next_cursor: None,
        };
        if !parent_available {
            return Ok(context);
        }
        // These existing canonical row keys are ordered repository/task/worktree,
        // then by typed identity. Keep a prefix, so a budget cut cannot skip keys.
        let candidates = self
            .repositories
            .values()
            .map(|(v, s)| ("repository", v.repository_id.to_string(), *s))
            .chain(
                self.tasks
                    .values()
                    .map(|(v, s)| ("task", v.task_id.to_string(), *s)),
            )
            .chain(
                self.worktrees
                    .values()
                    .map(|(v, s)| ("worktree", v.worktree_instance_id.to_string(), *s)),
            );
        for (kind, id, seq) in candidates {
            let key = format!("object:work:{kind}:{id}");
            if after.is_some_and(|after| key.as_str() <= after) {
                continue;
            }
            if std::time::Instant::now() >= deadline {
                context.complete = false;
                context.next_cursor = context.items.last().map(|item| item.row.row_id.clone());
                break;
            }
            let payload = match kind {
                "repository" if query.parent.is_none() => {
                    JournalPayload::RepositoryInstanceRecorded(Box::new(
                        self.repositories[&id.parse().map_err(|_| StoreError::StoreCorrupt)?]
                            .0
                            .clone(),
                    ))
                }
                "task" => {
                    let value = &self.tasks[&id.parse().map_err(|_| StoreError::StoreCorrupt)?].0;
                    if query
                        .parent
                        .is_some_and(|parent| !parent.directory_parent_of_task(value))
                    {
                        continue;
                    }
                    JournalPayload::TaskRecorded(Box::new(value.clone()))
                }
                "worktree" => {
                    let value =
                        &self.worktrees[&id.parse().map_err(|_| StoreError::StoreCorrupt)?].0;
                    if query.parent.is_some_and(|parent| {
                        parent
                            != ScopeBoundary::Repository {
                                repository_id: value.repository_instance_id,
                            }
                    }) {
                        continue;
                    }
                    JournalPayload::WorktreeInstanceRecorded(Box::new(value.clone()))
                }
                _ => continue,
            };
            let Some(row) = self.scope_fact_row(&payload, seq)? else {
                continue;
            };
            if context.items.len() == limit {
                context.next_cursor = context.items.last().map(|item| item.row.row_id.clone());
                break;
            }
            let (parent, repository, branch_ref) = match &payload {
                JournalPayload::RepositoryInstanceRecorded(value) => (
                    Some(ScopeBoundary::Repository {
                        repository_id: value.repository_id,
                    }),
                    None,
                    None,
                ),
                JournalPayload::WorktreeInstanceRecorded(value) => (
                    Some(ScopeBoundary::Worktree {
                        worktree_id: value.worktree_instance_id,
                    }),
                    self.repositories
                        .get(&value.repository_instance_id)
                        .map(|(v, _)| v.clone()),
                    value
                        .current_snapshot_id
                        .and_then(|id| self.worktree_snapshots.get(&id))
                        .and_then(|(v, _)| v.branch_ref.clone()),
                ),
                _ => (None, None, None),
            };
            let mut has_children = false;
            if let Some(parent) = parent {
                for (task, seq) in self.tasks.values() {
                    if std::time::Instant::now() >= deadline {
                        context.complete = false;
                        context.next_cursor =
                            context.items.last().map(|item| item.row.row_id.clone());
                        return Ok(context);
                    }
                    if !parent.directory_parent_of_task(task) {
                        continue;
                    }
                    if self.scope_fact_visible(
                        &JournalPayload::TaskRecorded(Box::new(task.clone())),
                        *seq,
                    )? {
                        has_children = true;
                        break;
                    }
                }
                if let ScopeBoundary::Repository { repository_id } = parent
                    && !has_children
                {
                    for (tree, seq) in self.worktrees.values() {
                        if std::time::Instant::now() >= deadline {
                            context.complete = false;
                            context.next_cursor =
                                context.items.last().map(|item| item.row.row_id.clone());
                            return Ok(context);
                        }
                        if tree.repository_instance_id != repository_id {
                            continue;
                        }
                        if self.scope_fact_visible(
                            &JournalPayload::WorktreeInstanceRecorded(Box::new(tree.clone())),
                            *seq,
                        )? {
                            has_children = true;
                            break;
                        }
                    }
                }
            }
            context.items.push(ScopeDirectoryCandidate {
                row,
                has_children,
                repository,
                branch_ref,
                sources_complete: false,
                source_rows: Vec::new(),
                source_scope_rows: Vec::new(),
                source_suppressed: false,
            });
        }
        let mut remaining = 64usize * 1024 * 1024;
        for item in &mut context.items {
            if item.row.object_kind.as_deref() != Some("task") {
                continue;
            }
            let id = item
                .row
                .object_id
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?
                .parse()
                .map_err(|_| StoreError::StoreCorrupt)?;
            let task = &self.tasks.get(&id).ok_or(StoreError::StoreCorrupt)?.0;
            item.sources_complete = !task.request_root_refs.is_empty();
            let mut observations = BTreeSet::new();
            for reference in &task.request_root_refs {
                if std::time::Instant::now() >= deadline {
                    item.sources_complete = false;
                    break;
                }
                let Some((selected, observation)) = self.directory_source_root(reference)? else {
                    item.sources_complete = false;
                    break;
                };
                if !observations.insert(observation) {
                    continue;
                }
                let mut sources =
                    self.capture_selected_items(vec![(selected, observation)], false)?;
                let source = sources.pop().ok_or(StoreError::StoreCorrupt)?;
                let bytes = source
                    .source_rows
                    .iter()
                    .chain(&source.scope_rows)
                    .map(|row| row.payload_json.as_ref().map_or(0, |value| value.len()) + 8192)
                    .sum::<usize>();
                let Some(next) = remaining.checked_sub(bytes) else {
                    item.sources_complete = false;
                    break;
                };
                remaining = next;
                item.source_rows.extend(source.source_rows);
                item.source_scope_rows.extend(source.scope_rows);
                item.source_suppressed |= source.suppressed;
            }
            if !item.sources_complete {
                item.source_rows.clear();
                item.source_scope_rows.clear();
                item.source_suppressed = false;
            }
        }
        Ok(context)
    }

    fn directory_source_root(
        &self,
        reference: &str,
    ) -> Result<Option<(ObjectRow, SourceObservationId)>, StoreError> {
        let receipt_prefix = "object:evidence:source_receipt:";
        let observation_prefix = "object:evidence:source_observation:";
        let surface_prefix = "projection:evidence_surface:";
        let mut selected = None;
        let mut observation = None;
        let raw = reference.strip_prefix(receipt_prefix).unwrap_or(reference);
        if let Ok(id) = raw.parse::<SourceReceiptId>()
            && raw == id.to_string()
            && let Some((value, seq)) = self.source_receipts.get(&id)
        {
            observation = Some(value.source_observation_id);
            selected = Some(source_receipt_row(value.as_ref(), *seq)?);
        }
        let raw = reference
            .strip_prefix(observation_prefix)
            .or_else(|| reference.strip_prefix(surface_prefix))
            .unwrap_or(reference);
        if let Ok(id) = raw.parse::<SourceObservationId>()
            && raw == id.to_string()
        {
            observation = Some(id);
            selected = if reference.starts_with(surface_prefix) {
                self.evidence_surfaces
                    .get(&id)
                    .map(|(value, seq)| surface_row(id, value.as_ref(), *seq))
                    .transpose()?
            } else if let Some((value, seq)) = self.source_observations.get(&id) {
                Some(source_observation_row(value.as_ref(), *seq)?)
            } else {
                self.evidence_surfaces
                    .get(&id)
                    .map(|(value, seq)| surface_row(id, value.as_ref(), *seq))
                    .transpose()?
            };
        }
        match (selected, observation) {
            (Some(row), Some(id)) => Ok(self
                .capture_product_rows(vec![row])?
                .pop()
                .map(|row| (row, id))),
            _ => Ok(None),
        }
    }

    pub(crate) fn memory_browse_context(
        &self,
        query: &MemoryBrowseQuery,
        after: Option<&MemoryBrowseCursor>,
        limit: usize,
        has_failed_job: bool,
    ) -> Result<MemoryBrowseContext, StoreError> {
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if after.is_some_and(|cursor| cursor.validate_for(query).is_err()) {
            return Err(StoreError::InvalidInput);
        }
        if limit == 0 || limit > 64 {
            return Err(StoreError::InvalidInput);
        }
        let scope = self.memory_scope_context(query.selection)?;
        let ProductDeletionIds {
            revision_ids: revisions,
            atom_ids: atoms,
            procedure_ids: procedures,
            membership_ids: memberships,
        } = product_deletion_ids(&self.deletions);
        let contracts = self.s23.deletion_owned_contracts(&revisions, &memberships);
        // No corpus clone or Web index: consume one current record at a time
        // and retain only the selected limit+1. Historical reads stay separate.
        let rows = self
            .atoms
            .values()
            .filter(|(value, _)| {
                !atoms.contains(&value.atom_id) && !revisions.contains(&value.revision_id)
            })
            .map(|(value, seq)| {
                let mut row = semantic_atom_row(
                    value,
                    &JournalPayload::AtomRecorded(Box::new(value.clone())),
                    *seq,
                )?;
                row.support_state = self
                    .s23
                    .atom_support_state_excluding(value.revision_id, &contracts)
                    .map(str::to_owned);
                Ok(row)
            })
            .chain(
                self.s23
                    .all_membership_revisions()
                    .filter(|value| {
                        !revisions.contains(&value.membership_revision_id)
                            && !memberships.contains(&value.core_membership_id)
                            && self
                                .s23
                                .current_membership(value.core_membership_id)
                                .is_some_and(|current| {
                                    current.membership_revision_id == value.membership_revision_id
                                })
                    })
                    .map(|value| {
                        self.s23
                            .membership_row(value.membership_revision_id, PROJECTION_GENERATION)
                    }),
            )
            .chain(
                self.procedure
                    .all_revisions()
                    .filter(|value| {
                        !revisions.contains(&value.revision_id)
                            && self.procedure.is_current_revision_id(value.revision_id)
                    })
                    .map(|value| {
                        self.procedure.revision_row(
                            value.revision_id,
                            PROJECTION_GENERATION,
                            self.s23
                                .successor_support_state_excluding(value.revision_id, &contracts),
                        )
                    }),
            )
            .chain(
                self.proposals
                    .values()
                    .filter(|(value, _)| {
                        !revisions.contains(&value.proposal_revision_id)
                            && !value
                                .base_revision_id
                                .is_some_and(|id| revisions.contains(&id))
                            && !proposal_targets_deleted(value, &atoms, &procedures, &memberships)
                            && (revisions.is_empty()
                                || !self.proposal_revisions.values().any(|(candidate, _)| {
                                    candidate.proposal_id == value.proposal_id
                                        && proposal_targets_deleted(
                                            candidate,
                                            &atoms,
                                            &procedures,
                                            &memberships,
                                        )
                                }))
                    })
                    .map(|(value, seq)| {
                        semantic_proposal_row(
                            value,
                            &JournalPayload::RevisionProposalRecorded(Box::new(value.clone())),
                            *seq,
                        )
                    }),
            )
            .chain(self.synthesis.digests().values().map(|(value, seq)| {
                synthesis::digest_row(value.semantic_digest_id, value.clone(), *seq)
            }));
        let rank = |seq: u64, key: &str| {
            (
                match query.order {
                    MemoryBrowseOrder::RecordedNewest => u64::MAX - seq,
                    MemoryBrowseOrder::RecordedOldest => seq,
                },
                key.to_owned(),
            )
        };
        let after_rank = after.map(|value| rank(value.source_event_seq, &value.row_id));
        let mut selected = BTreeMap::new();
        let (mut total_count, mut matching_count, mut unresolved_scope_count) =
            (0_u64, 0_u64, 0_u64);
        for row in rows {
            for row in filter_product_rows(
                vec![row?],
                &self.deletions,
                &self.scope_purges,
                self.repository_closures.values(),
            )? {
                let ownership = self.memory_record_scope(&row)?;
                if ownership.is_none() {
                    unresolved_scope_count += 1;
                }
                if !scope.available
                    || !scope.includes(query.selection, query.include_global, ownership.as_deref())
                {
                    continue;
                }
                total_count += 1;
                let kind = match row.object_kind.as_deref() {
                    Some("semantic_digest") => MemoryReadingKind::Summaries,
                    Some("atom_revision" | "core_membership") => {
                        MemoryReadingKind::FactsAndConstraints
                    }
                    Some("procedure_revision") => MemoryReadingKind::Methods,
                    Some("revision_proposal_revision") => MemoryReadingKind::References,
                    _ => return Err(StoreError::StoreCorrupt),
                };
                if (query.kind != MemoryReadingKind::All && query.kind != kind)
                    || query
                        .epistemic_status
                        .is_some_and(|value| row.epistemic.as_deref() != Some(value.as_str()))
                    || query
                        .authority
                        .is_some_and(|value| row.authority.as_deref() != Some(value.as_str()))
                    || query
                        .atom_lifecycle
                        .is_some_and(|value| row.lifecycle.as_deref() != Some(value.as_str()))
                {
                    continue;
                }
                matching_count += 1;
                let position = rank(row.source_event_seq, &row.row_id);
                if after_rank.as_ref().is_some_and(|after| position <= *after) {
                    continue;
                }
                selected.insert(position, row);
                if selected.len() > limit + 1 {
                    selected.pop_last();
                }
            }
        }
        let mut items = selected.into_values().collect::<Vec<_>>();
        let next_cursor = if items.len() > limit {
            let last = &items[limit - 1];
            Some(
                serde_json::to_string(&MemoryBrowseCursor {
                    frontier: self.frontier,
                    query: query.clone(),
                    source_event_seq: last.source_event_seq,
                    row_id: last.row_id.clone(),
                })
                .map_err(|_| StoreError::StoreCorrupt)?,
            )
        } else {
            None
        };
        items.truncate(limit);
        let current_proposal_revisions = items
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("revision_proposal_revision"))
            .filter_map(|row| row.object_id.as_deref()?.parse::<RevisionProposalId>().ok())
            .filter_map(|id| {
                self.proposals
                    .get(&id)
                    .map(|(value, _)| value.proposal_revision_id)
            })
            .collect();
        Ok(MemoryBrowseContext {
            page: MemoriesCurrentContext {
                frontier: self.frontier,
                has_failed_job,
                items,
                current_proposal_revisions,
                next_cursor,
            },
            total_count: scope.available.then_some(total_count),
            matching_count: scope.available.then_some(matching_count),
            scope_available: scope.available,
            counts_complete: scope.available
                && scope.complete
                && (query.selection == evertrace_domain::query::MemoryScopeSelection::All
                    || unresolved_scope_count == 0),
            unresolved_scope_count,
        })
    }

    fn memory_scope_context(
        &self,
        selection: evertrace_domain::query::MemoryScopeSelection,
    ) -> Result<MemoryScopeContext, StoreError> {
        use evertrace_domain::query::MemoryScopeSelection as S;
        let mut context = MemoryScopeContext {
            available: true,
            complete: true,
            ..Default::default()
        };
        let repository_visible = |id: &evertrace_domain::ids::RepositoryId| {
            self.repositories.get(id).map_or(Ok(false), |(repo, seq)| {
                self.scope_fact_visible(
                    &JournalPayload::RepositoryInstanceRecorded(Box::new(repo.clone())),
                    *seq,
                )
            })
        };
        let worktree_visible = |tree: &evertrace_domain::repository::WorktreeInstance, seq| {
            self.scope_fact_visible(
                &JournalPayload::WorktreeInstanceRecorded(Box::new(tree.clone())),
                seq,
            )
        };
        match selection {
            S::All | S::Global | S::Unassigned => return Ok(context),
            S::Task { task_id } => {
                let Some((task, seq)) = self.tasks.get(&task_id) else {
                    context.available = false;
                    return Ok(context);
                };
                if !self.scope_fact_visible(
                    &JournalPayload::TaskRecorded(Box::new(task.clone())),
                    *seq,
                )? {
                    context.available = false;
                    return Ok(context);
                }
                context.tasks.insert(task_id);
                for membership in &task.scope_memberships {
                    if let Some(id) = membership.repository_instance_id {
                        if repository_visible(&id)? {
                            context.repositories.insert(id);
                        } else {
                            context.complete = false;
                        }
                    }
                    for id in &membership.worktree_instance_ids {
                        match self.worktrees.get(id) {
                            Some((tree, seq))
                                if Some(tree.repository_instance_id)
                                    == membership.repository_instance_id
                                    && context
                                        .repositories
                                        .contains(&tree.repository_instance_id)
                                    && worktree_visible(tree, *seq)? =>
                            {
                                context.worktrees.insert(*id);
                            }
                            _ => context.complete = false,
                        }
                    }
                }
            }
            S::Repository { repository_id } => {
                if !repository_visible(&repository_id)? {
                    context.available = false;
                    return Ok(context);
                }
                context.repositories.insert(repository_id);
                for (tree, seq) in self
                    .worktrees
                    .values()
                    .filter(|(tree, _)| tree.repository_instance_id == repository_id)
                {
                    if worktree_visible(tree, *seq)? {
                        context.worktrees.insert(tree.worktree_instance_id);
                    }
                }
                for (task, seq) in self.tasks.values().filter(|(task, _)| {
                    task.scope_memberships
                        .iter()
                        .any(|membership| membership.repository_instance_id == Some(repository_id))
                }) {
                    if self.scope_fact_visible(
                        &JournalPayload::TaskRecorded(Box::new(task.clone())),
                        *seq,
                    )? {
                        context.tasks.insert(task.task_id);
                    }
                }
            }
            S::Worktree { worktree_id } => {
                let Some((tree, seq)) = self.worktrees.get(&worktree_id) else {
                    context.available = false;
                    return Ok(context);
                };
                if !self.scope_fact_visible(
                    &JournalPayload::WorktreeInstanceRecorded(Box::new(tree.clone())),
                    *seq,
                )? {
                    context.available = false;
                    return Ok(context);
                }
                if repository_visible(&tree.repository_instance_id)? {
                    context.repositories.insert(tree.repository_instance_id);
                } else {
                    context.complete = false;
                }
                context.worktrees.insert(worktree_id);
                for (task, seq) in self.tasks.values().filter(|(task, _)| {
                    task.scope_memberships
                        .iter()
                        .any(|membership| membership.worktree_instance_ids.contains(&worktree_id))
                }) {
                    if self.scope_fact_visible(
                        &JournalPayload::TaskRecorded(Box::new(task.clone())),
                        *seq,
                    )? {
                        context.tasks.insert(task.task_id);
                    }
                }
            }
        }
        Ok(context)
    }

    // Scope comes from each owning typed record, never from missing SQL columns.
    // In particular, proposals with no base are not silently classified global.
    fn memory_record_scope(
        &self,
        row: &ObjectRow,
    ) -> Result<Option<Vec<evertrace_domain::semantic::AtomScope>>, StoreError> {
        use evertrace_domain::{
            ids::SemanticDigestId,
            semantic::{
                AtomProposalPayload as A, CoreMembershipProposalPayload as C, ProposalPayload as P,
            },
        };
        let revision = || {
            row.current_revision_id
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?
                .parse::<RevisionId>()
                .map_err(|_| StoreError::StoreCorrupt)
        };
        let scopes = match row.object_kind.as_deref() {
            Some("atom_revision") => vec![
                self.atom_revisions
                    .get(&revision()?)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0
                    .scope
                    .clone(),
            ],
            Some("core_membership") => vec![core_scope(
                &self
                    .s23
                    .membership_revision(revision()?)
                    .ok_or(StoreError::StoreCorrupt)?
                    .scope_identity,
            )],
            Some("procedure_revision") => vec![procedure_scope(
                &self
                    .procedure
                    .revision(revision()?)
                    .ok_or(StoreError::StoreCorrupt)?
                    .draft
                    .scope,
            )],
            Some("semantic_digest") => {
                let id = row
                    .object_id
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?
                    .parse::<SemanticDigestId>()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let digest = &self
                    .synthesis
                    .digests()
                    .get(&id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                if let Some(task_id) = digest.task_id {
                    vec![evertrace_domain::semantic::AtomScope::Task { task_id }]
                } else if let (Some(repository_id), Some(worktree_id)) =
                    (digest.repository_id, digest.worktree_id)
                {
                    vec![evertrace_domain::semantic::AtomScope::Worktree {
                        repository_instance_id: repository_id,
                        worktree_instance_id: worktree_id,
                    }]
                } else if let Some(repository_id) = digest.repository_id {
                    vec![evertrace_domain::semantic::AtomScope::Repository {
                        repository_instance_id: repository_id,
                    }]
                } else {
                    Vec::new()
                }
            }
            Some("revision_proposal_revision") => {
                let proposal = &self
                    .proposal_revisions
                    .get(&revision()?)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                match &proposal.payload {
                    P::Atom(value) => match value.as_ref() {
                        A::Create { draft }
                        | A::Replace { draft }
                        | A::Merge { draft, .. }
                        | A::Reclassify { draft } => vec![draft.scope.clone()],
                        A::Split { drafts } => {
                            drafts.iter().map(|draft| draft.scope.clone()).collect()
                        }
                        A::Deprecate { .. } => {
                            let Some((atom, _)) = proposal
                                .base_revision_id
                                .and_then(|id| self.atom_revisions.get(&id))
                            else {
                                return Ok(None);
                            };
                            vec![atom.scope.clone()]
                        }
                    },
                    P::Procedure(value) => vec![procedure_scope(&value.draft().scope)],
                    P::CoreMembership(value) => match value.as_ref() {
                        C::Create { scope_identity, .. }
                        | C::ResolveConflict { scope_identity, .. } => {
                            vec![core_scope(scope_identity)]
                        }
                    },
                    P::ReservedTarget { .. } => return Ok(None),
                }
            }
            _ => return Err(StoreError::StoreCorrupt),
        };
        Ok(Some(scopes))
    }
}

#[derive(Default)]
struct MemoryScopeContext {
    available: bool,
    complete: bool,
    tasks: BTreeSet<TaskId>,
    repositories: BTreeSet<RepositoryId>,
    worktrees: BTreeSet<WorktreeId>,
}

impl MemoryScopeContext {
    fn includes(
        &self,
        selection: evertrace_domain::query::MemoryScopeSelection,
        include_global: bool,
        scopes: Option<&[evertrace_domain::semantic::AtomScope]>,
    ) -> bool {
        use evertrace_domain::{query::MemoryScopeSelection as S, semantic::AtomScope as A};
        if selection == S::All {
            return true;
        }
        let Some(scopes) = scopes else { return false };
        if selection == S::Unassigned {
            return scopes.is_empty();
        }
        scopes.iter().any(|scope| match scope {
            A::Global => selection == S::Global || include_global,
            A::Task { task_id } => self.tasks.contains(task_id),
            A::Repository {
                repository_instance_id,
            } => self.repositories.contains(repository_instance_id),
            A::Worktree {
                worktree_instance_id,
                ..
            } => self.worktrees.contains(worktree_instance_id),
        })
    }
}

fn core_scope(
    scope: &evertrace_domain::semantic::CoreScopeIdentity,
) -> evertrace_domain::semantic::AtomScope {
    use evertrace_domain::semantic::{AtomScope as A, CoreScopeIdentity as C};
    match scope {
        C::Global => A::Global,
        C::Repository(repository_id) => A::Repository {
            repository_instance_id: *repository_id,
        },
    }
}
fn procedure_scope(
    scope: &evertrace_domain::procedure::ProcedureScope,
) -> evertrace_domain::semantic::AtomScope {
    use evertrace_domain::{procedure::ProcedureScope as P, semantic::AtomScope as A};
    match scope {
        P::Global => A::Global,
        P::Repository { repository_id } => A::Repository {
            repository_instance_id: *repository_id,
        },
        P::Worktree {
            repository_id,
            worktree_id,
        } => A::Worktree {
            repository_instance_id: *repository_id,
            worktree_instance_id: *worktree_id,
        },
    }
}
