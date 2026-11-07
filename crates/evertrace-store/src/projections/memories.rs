//! Request-local human metadata browsing over the canonical admission indexes.
use super::*;
use evertrace_domain::query::{
    MemoryBrowseCursor, MemoryBrowseOrder, MemoryBrowseQuery, MemoryReadingKind,
};

#[derive(Debug)]
pub struct MemoryBrowseContext {
    pub page: MemoriesCurrentContext,
    pub event_times: BTreeMap<u64, i64>,
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
        mut journal_times: Option<&mut crate::sqlite_state::JournalTimeReader<'_>>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<MemoryBrowseContext, StoreError> {
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if after.is_some_and(|cursor| cursor.validate_for(query).is_err())
            || !(1..=64).contains(&limit)
        {
            return Err(StoreError::InvalidInput);
        }
        let scope = self.memory_scope_context(query.selection)?;
        let deleted = product_deletion_ids(&self.deletions);
        let contracts = self
            .scenario_core
            .deletion_owned_contracts(&deleted.revision_ids, &deleted.membership_ids);
        let purged_repositories = self
            .scope_purges
            .events()
            .map(|event| event.target.repository_id())
            .collect::<BTreeSet<_>>();
        // Borrow current typed records. Full canonical rows are formed only
        // after visibility, scope, filters, counts and keyset selection.
        let candidates = self
            .atoms
            .values()
            .map(|(v, seq)| Ok(MemoriesCandidate::Atom(v, *seq)))
            .chain(
                self.scenario_core
                    .all_membership_revisions()
                    .filter(|v| {
                        self.scenario_core
                            .current_membership(v.core_membership_id)
                            .is_some_and(|current| {
                                current.membership_revision_id == v.membership_revision_id
                            })
                    })
                    .map(|v| {
                        self.scenario_core
                            .membership_revision_entry(v.membership_revision_id)
                            .map(|(_, seq)| MemoriesCandidate::Membership(v, seq))
                            .ok_or(StoreError::StoreCorrupt)
                    }),
            )
            .chain(
                self.procedure
                    .all_revisions()
                    .filter(|v| self.procedure.is_current_revision_id(v.revision_id))
                    .map(|v| {
                        self.procedure
                            .revision_entry(v.revision_id)
                            .map(|(_, seq)| MemoriesCandidate::Procedure(v, seq))
                            .ok_or(StoreError::StoreCorrupt)
                    }),
            )
            .chain(
                self.proposals
                    .values()
                    .filter(|(v, _)| {
                        !v.base_revision_id
                            .is_some_and(|id| deleted.revision_ids.contains(&id))
                            && (deleted.revision_ids.is_empty()
                                || !self.proposal_revisions.values().any(|(previous, _)| {
                                    previous.proposal_id == v.proposal_id
                                        && proposal_targets_deleted(
                                            previous,
                                            &deleted.atom_ids,
                                            &deleted.procedure_ids,
                                            &deleted.membership_ids,
                                        )
                                }))
                    })
                    .map(|(v, seq)| Ok(MemoriesCandidate::Proposal(v, *seq))),
            )
            .chain(
                self.synthesis
                    .digests()
                    .values()
                    .map(|(v, seq)| Ok(MemoriesCandidate::Digest(v, *seq))),
            );
        let newest = matches!(
            query.order,
            MemoryBrowseOrder::RecordedNewest | MemoryBrowseOrder::EventNewest
        );
        let rank = |seq: u64, key: String, event: Option<i64>| -> Result<_, StoreError> {
            let event = if query.order.uses_event_time() {
                i128::from(event.ok_or(StoreError::StoreCorrupt)?)
            } else {
                0
            };
            let seq = i128::from(seq);
            Ok((
                if newest { -event } else { event },
                if newest { -seq } else { seq },
                key,
            ))
        };
        let after_rank = after
            .map(|v| rank(v.source_event_seq, v.row_id.clone(), v.event_time_us))
            .transpose()?;
        let mut after_verified = after.is_none() || !query.order.uses_event_time();
        let mut selected = BTreeMap::new();
        let (mut total_count, mut matching_count, mut unresolved_scope_count) =
            (0_u64, 0_u64, 0_u64);
        for candidate in candidates {
            if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)) {
                return Err(StoreError::Io);
            }
            let candidate = candidate?;
            if candidate.product_deleted(
                &deleted.revision_ids,
                &deleted.atom_ids,
                &deleted.procedure_ids,
                &deleted.membership_ids,
            ) {
                continue;
            }
            if !purged_repositories.is_empty()
                && (candidate
                    .repository_id()
                    .is_some_and(|id| purged_repositories.contains(&id))
                    || self
                        .repository_closures
                        .values()
                        .any(|closure| closure.references_memory(candidate)))
            {
                continue;
            }
            let ownership = self.memory_record_scope(candidate);
            if ownership.is_none() {
                unresolved_scope_count += 1;
            }
            if !scope.available
                || !scope.includes(query.selection, query.include_global, ownership.as_deref())
            {
                continue;
            }
            total_count += 1;
            if !candidate.matches_query(query) {
                continue;
            }
            let times = if query.time_range.is_some() || query.order.uses_event_time() {
                Some(journal_times.as_mut().ok_or(StoreError::StoreCorrupt)?(
                    candidate.source_event_seq(),
                )?)
            } else {
                None
            };
            if let Some(range) = &query.time_range {
                let (occurred, ingested) = times.ok_or(StoreError::StoreCorrupt)?;
                if !range.contains(occurred, ingested) {
                    continue;
                }
            }
            matching_count += 1;
            let event = times.map(|value| value.0);
            let position = rank(candidate.source_event_seq(), candidate.row_id(), event)?;
            if let Some(after) = after
                && query.order.uses_event_time()
                && candidate.source_event_seq() == after.source_event_seq
                && position.2 == after.row_id
            {
                after_verified = event == after.event_time_us;
            }
            if after_rank.as_ref().is_some_and(|after| position <= *after) {
                continue;
            }
            selected.insert(position, (candidate, event));
            if selected.len() > limit + 1 {
                selected.pop_last();
            }
        }
        if !after_verified {
            return Err(StoreError::InvalidInput);
        }
        let mut selected = selected.into_iter().collect::<Vec<_>>();
        let next_cursor = if selected.len() > limit {
            let (position, (last, event)) = &selected[limit - 1];
            Some(
                serde_json::to_string(&MemoryBrowseCursor {
                    frontier: self.frontier,
                    query: query.clone(),
                    event_time_us: if query.order.uses_event_time() {
                        *event
                    } else {
                        None
                    },
                    source_event_seq: last.source_event_seq(),
                    row_id: position.2.clone(),
                })
                .map_err(|_| StoreError::StoreCorrupt)?,
            )
        } else {
            None
        };
        selected.truncate(limit);
        if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)) {
            return Err(StoreError::Io);
        }
        let expected_count = selected.len();
        let mut event_times = BTreeMap::new();
        let items = selected
            .into_iter()
            .map(|(_, (candidate, event))| {
                if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)) {
                    return Err(StoreError::Io);
                }
                if query.order.uses_event_time()
                    && let Some(event) = event
                {
                    event_times.insert(candidate.source_event_seq(), event);
                }
                self.memory_candidate_row(candidate, &contracts)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Keep the existing canonical selected-row check as well. A divergence
        // is corruption, not a silently shorter page with overstated counts.
        let items = filter_product_rows(
            items,
            &self.deletions,
            &self.scope_purges,
            self.repository_closures.values(),
        )?;
        if items.len() != expected_count {
            return Err(StoreError::StoreCorrupt);
        }
        let current_proposal_revisions = items
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("revision_proposal_revision"))
            .filter_map(|row| row.object_id.as_deref()?.parse::<RevisionProposalId>().ok())
            .filter_map(|id| self.proposals.get(&id).map(|(v, _)| v.proposal_revision_id))
            .collect();
        Ok(MemoryBrowseContext {
            event_times,
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

    pub(super) fn memory_candidate_row(
        &self,
        candidate: MemoriesCandidate<'_>,
        contracts: &BTreeSet<RevisionId>,
    ) -> Result<ObjectRow, StoreError> {
        let row = match candidate {
            MemoriesCandidate::Atom(value, seq) => {
                let mut row = semantic_atom_row(
                    value,
                    &JournalPayload::AtomRecorded(Box::new(value.clone())),
                    seq,
                )?;
                row.support_state = self
                    .scenario_core
                    .atom_support_state_excluding(value.revision_id, contracts)
                    .map(str::to_owned);
                row
            }
            MemoriesCandidate::Membership(value, _) => self
                .scenario_core
                .membership_row(value.membership_revision_id, PROJECTION_GENERATION)?,
            MemoriesCandidate::Procedure(value, _) => self.procedure.revision_row(
                value.revision_id,
                PROJECTION_GENERATION,
                self.scenario_core
                    .successor_support_state_excluding(value.revision_id, contracts),
            )?,
            MemoriesCandidate::Proposal(value, seq) => semantic_proposal_row(
                value,
                &JournalPayload::RevisionProposalRecorded(Box::new(value.clone())),
                seq,
            )?,
            MemoriesCandidate::Digest(value, seq) => {
                synthesis::digest_row(value.semantic_digest_id, value.clone(), seq)?
            }
        };
        if row.row_id != candidate.row_id() || row.source_event_seq != candidate.source_event_seq()
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(row)
    }

    pub(super) fn memory_scope_context(
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
    pub(super) fn memory_record_scope(
        &self,
        candidate: MemoriesCandidate<'_>,
    ) -> Option<Vec<evertrace_domain::semantic::AtomScope>> {
        use evertrace_domain::semantic::{
            AtomProposalPayload as A, CoreMembershipProposalPayload as C, ProposalPayload as P,
        };
        let scopes = match candidate {
            MemoriesCandidate::Atom(value, _) => vec![value.scope.clone()],
            MemoriesCandidate::Membership(value, _) => vec![core_scope(&value.scope_identity)],
            MemoriesCandidate::Procedure(value, _) => vec![procedure_scope(&value.draft.scope)],
            MemoriesCandidate::Digest(digest, _) => {
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
            MemoriesCandidate::Proposal(proposal, _) => match &proposal.payload {
                P::Atom(value) => match value.as_ref() {
                    A::Create { draft }
                    | A::Replace { draft }
                    | A::Merge { draft, .. }
                    | A::Reclassify { draft } => vec![draft.scope.clone()],
                    A::Split { drafts } => drafts.iter().map(|draft| draft.scope.clone()).collect(),
                    A::Deprecate { .. } => {
                        let (atom, _) = proposal
                            .base_revision_id
                            .and_then(|id| self.atom_revisions.get(&id))?;
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
                P::ReservedTarget { .. } => return None,
            },
        };
        Some(scopes)
    }
}

impl<'a> MemoriesCandidate<'a> {
    pub(crate) fn from_payload(payload: &'a JournalPayload, seq: u64) -> Option<Self> {
        Some(match payload {
            JournalPayload::AtomRecorded(v) => Self::Atom(v, seq),
            JournalPayload::CoreMembershipRecorded(v) => Self::Membership(v, seq),
            JournalPayload::ProcedureRevisionRecorded(v) => Self::Procedure(v, seq),
            JournalPayload::RevisionProposalRecorded(v) => Self::Proposal(v, seq),
            JournalPayload::SemanticDigestRecorded(v) => Self::Digest(v, seq),
            _ => return None,
        })
    }

    pub(super) fn source_event_seq(self) -> u64 {
        match self {
            Self::Atom(_, seq)
            | Self::Membership(_, seq)
            | Self::Procedure(_, seq)
            | Self::Proposal(_, seq)
            | Self::Digest(_, seq) => seq,
        }
    }

    pub(super) fn row_id(self) -> String {
        match self {
            Self::Atom(v, _) => format!("object:atom:atom_revision:{}", v.revision_id),
            Self::Membership(v, _) => {
                format!("object:atom:core_membership:{}", v.membership_revision_id)
            }
            Self::Procedure(v, _) => {
                format!("object:procedure:{}:{}", v.procedure_id, v.revision_id)
            }
            Self::Proposal(v, _) => format!(
                "object:revision_proposal:revision_proposal_revision:{}",
                v.proposal_revision_id
            ),
            Self::Digest(v, _) => format!("object:work:semantic_digest:{}", v.semantic_digest_id),
        }
    }

    pub(super) fn repository_id(self) -> Option<RepositoryId> {
        match self {
            Self::Atom(v, _) => v.scope.repository_id(),
            Self::Membership(v, _) => core_scope(&v.scope_identity).repository_id(),
            Self::Procedure(v, _) => procedure_scope(&v.draft.scope).repository_id(),
            Self::Digest(v, _) => v.repository_id,
            // Proposal projection columns do not define its owning scope.
            Self::Proposal(_, _) => None,
        }
    }

    fn matches_query(self, query: &MemoryBrowseQuery) -> bool {
        let (kind, epistemic, authority, lifecycle) = match self {
            Self::Atom(v, _) => (
                MemoryReadingKind::FactsAndConstraints,
                Some(v.epistemic_status.as_str()),
                Some(v.authority.as_str()),
                Some(v.lifecycle_status.as_str()),
            ),
            Self::Membership(v, _) => (
                MemoryReadingKind::FactsAndConstraints,
                None,
                None,
                Some(if v.active { "active" } else { "inactive" }),
            ),
            Self::Procedure(_, _) => (MemoryReadingKind::Methods, None, None, Some("active")),
            Self::Proposal(v, _) => (
                MemoryReadingKind::References,
                Some("not_applicable"),
                Some("none"),
                Some(v.status.as_str()),
            ),
            Self::Digest(v, _) => (
                MemoryReadingKind::Summaries,
                Some("derived"),
                Some(if v.source_target.is_some() {
                    "agent_inferred"
                } else {
                    "none"
                }),
                Some("immutable"),
            ),
        };
        (query.kind == MemoryReadingKind::All || query.kind == kind)
            && query
                .epistemic_status
                .is_none_or(|v| epistemic == Some(v.as_str()))
            && query
                .authority
                .is_none_or(|v| authority == Some(v.as_str()))
            && query
                .atom_lifecycle
                .is_none_or(|v| lifecycle == Some(v.as_str()))
    }

    // The same five-family product deletion predicate is used by the canonical
    // row filter and by metadata selection before counts/paging.
    pub(crate) fn product_deleted(
        self,
        revisions: &BTreeSet<RevisionId>,
        atoms: &BTreeSet<AtomId>,
        procedures: &BTreeSet<evertrace_domain::ids::ProcedureId>,
        memberships: &BTreeSet<evertrace_domain::ids::CoreMembershipId>,
    ) -> bool {
        match self {
            Self::Atom(v, _) => revisions.contains(&v.revision_id) || atoms.contains(&v.atom_id),
            Self::Membership(v, _) => {
                revisions.contains(&v.membership_revision_id)
                    || memberships.contains(&v.core_membership_id)
                    || revisions.contains(&v.atom_revision_id)
            }
            Self::Procedure(v, _) => {
                revisions.contains(&v.revision_id) || procedures.contains(&v.procedure_id)
            }
            Self::Proposal(v, _) => {
                revisions.contains(&v.proposal_revision_id)
                    || proposal_targets_deleted(v, atoms, procedures, memberships)
            }
            Self::Digest(v, _) => v.selected_direct_refs.iter().any(|r| {
                r.parse::<RevisionId>()
                    .is_ok_and(|id| revisions.contains(&id))
            }),
        }
    }
}

impl RepositoryClosureKeys {
    // Borrowing entry for the existing repository product predicate. The
    // JournalPayload path delegates here too; this is not a second policy.
    pub(super) fn references_memory(&self, candidate: MemoriesCandidate<'_>) -> bool {
        let Some(repository_id) = self.repository_id else {
            return false;
        };
        match candidate {
            MemoriesCandidate::Atom(value, _) => {
                self.atom_ids.contains(&value.atom_id)
                    || self.revision_ids.contains(&value.revision_id)
                    || atom_scope_repository(&value.scope, repository_id, &self.task_ids)
                    || value
                        .source_observation_refs
                        .iter()
                        .any(|id| self.source_observation_ids.contains(id))
                    || value.evidence_refs.iter().any(|reference| {
                        typed_text_references_target(
                            reference,
                            &self.source_observation_ids,
                            &self.source_receipt_ids,
                            &self.revision_ids,
                        )
                    })
                    || value
                        .parent_revision_id
                        .iter()
                        .chain(&value.value.critical_revision_refs)
                        .chain(&value.supersedes_revision_refs)
                        .chain(&value.supports_revision_refs)
                        .chain(&value.contradicts_revision_refs)
                        .any(|id| self.revision_ids.contains(id))
                    || value
                        .accepted_proposal_id
                        .is_some_and(|id| self.proposal_ids.contains(&id))
                    || value
                        .accepted_proposal_revision_id
                        .is_some_and(|id| self.proposal_revision_ids.contains(&id))
            }
            MemoriesCandidate::Membership(value, _) => {
                self.membership_ids.contains(&value.core_membership_id)
                    || self.revision_ids.contains(&value.membership_revision_id)
                    || self.revision_ids.contains(&value.atom_revision_id)
                    || self.revision_ids.contains(&value.support_contract_ref)
                    || value
                        .authorization_revision_refs
                        .iter()
                        .any(|id| self.revision_ids.contains(id))
                    || value
                        .supersedes_membership_revision_id
                        .is_some_and(|id| self.revision_ids.contains(&id))
                    || self.revision_ids.contains(&value.created_by_acceptance_ref)
            }
            MemoriesCandidate::Procedure(value, _) => self.references_procedure(value),
            MemoriesCandidate::Proposal(value, _) => self.references_proposal(value),
            MemoriesCandidate::Digest(value, _) => self.references_digest(value),
        }
    }
}

#[derive(Default)]
pub(super) struct MemoryScopeContext {
    pub(super) available: bool,
    pub(super) complete: bool,
    tasks: BTreeSet<TaskId>,
    repositories: BTreeSet<RepositoryId>,
    worktrees: BTreeSet<WorktreeId>,
}

impl MemoryScopeContext {
    pub(super) fn includes(
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
