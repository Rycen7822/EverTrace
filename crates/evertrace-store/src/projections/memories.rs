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
