//! Request-local human directory over current typed identities; no discovery scan.
use super::{HumanGovernanceError, HumanGovernanceService, export, presentation};
use evertrace_domain::{
    query::{
        MemoryScopeSelection as Selection, ScopeBoundary, ScopeDirectoryCursor,
        ScopeDirectoryEntry, ScopeDirectoryPage, ScopeDirectoryQuery,
        ScopeReadRestriction as Restriction, ScopeTitleState,
    },
    repository::{RepositoryInstance, WorktreeLifecycle},
    work::Task,
};
use evertrace_store::{JournalPayload, repository::RepositoryCurrentView};
use std::{collections::BTreeMap, time::Instant};

impl HumanGovernanceService {
    pub async fn scope_directory(
        &self,
        query: ScopeDirectoryQuery,
        expected_frontier: Option<u64>,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<ScopeDirectoryPage, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if !(1..=64).contains(&limit) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let cursor = after
            .map(|value| {
                if value.len() > 2048 {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                let cursor: ScopeDirectoryCursor =
                    serde_json::from_str(value).map_err(|_| HumanGovernanceError::InvalidInput)?;
                cursor
                    .validate_for(&query)
                    .map_err(|_| HumanGovernanceError::InvalidInput)?;
                if expected_frontier != Some(cursor.frontier) {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                Ok(cursor)
            })
            .transpose()?;
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if expected_frontier.is_some_and(|value| value != snapshot.frontier) {
            return Ok(Err(snapshot.frontier));
        }
        let repositories = RepositoryCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut tasks = BTreeMap::new();
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("task"))
        {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let JournalPayload::TaskRecorded(task) = payload else {
                return Err(HumanGovernanceError::Store);
            };
            tasks.insert(task.task_id, (task, row));
        }
        let parent_available = match query.parent {
            None => true,
            Some(ScopeBoundary::Task { task_id }) => tasks.contains_key(&task_id),
            Some(ScopeBoundary::Repository { repository_id }) => {
                repositories.repositories.contains_key(&repository_id)
            }
            Some(ScopeBoundary::Worktree { worktree_id }) => {
                repositories.worktrees.contains_key(&worktree_id)
            }
        };
        let mut page = ScopeDirectoryPage {
            frontier: snapshot.frontier,
            query: query.clone(),
            parent_available,
            complete: parent_available,
            names_complete: parent_available,
            items: Vec::new(),
            next_cursor: None,
        };
        if !parent_available {
            return Ok(Ok(page));
        }
        let mut rows = snapshot
            .data_rows()
            .filter(|row| {
                matches!(
                    row.object_kind.as_deref(),
                    Some("repository" | "worktree" | "task")
                )
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        let deadline = Instant::now() + presentation::READ_DEADLINE;
        let mut index = None;
        let mut last = cursor.as_ref().map(|value| value.after_key.clone());
        let needle = query.name.to_lowercase();
        for row in rows.into_iter().filter(|row| {
            cursor
                .as_ref()
                .is_none_or(|after| row.row_id > after.after_key)
        }) {
            if Instant::now() > deadline {
                page.complete = false;
                page.next_cursor = directory_cursor(snapshot.frontier, &query, last.as_deref())?;
                break;
            }
            let mut entry = match row.object_kind.as_deref() {
                Some("repository") => {
                    let id = row
                        .object_id
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?
                        .parse()
                        .map_err(|_| HumanGovernanceError::Store)?;
                    let repo = repositories
                        .repositories
                        .get(&id)
                        .ok_or(HumanGovernanceError::Store)?;
                    if query.parent.is_some() {
                        last = Some(row.row_id.clone());
                        continue;
                    }
                    ScopeDirectoryEntry {
                        stable_key: row.row_id.clone(),
                        selection: Selection::Repository { repository_id: id },
                        label: path_label(&repo.current_path),
                        title_state: ScopeTitleState::Metadata,
                        path_hint: Some(repo.current_path.clone()),
                        branch_hint: None,
                        lifecycle: None,
                        restrictions: repo_restrictions(Some(repo)),
                        has_children: repositories
                            .worktrees
                            .values()
                            .any(|tree| tree.repository_instance_id == id)
                            || tasks.values().any(|(task, _)| {
                                task_in(task, ScopeBoundary::Repository { repository_id: id })
                            }),
                    }
                }
                Some("worktree") => {
                    let id = row
                        .object_id
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?
                        .parse()
                        .map_err(|_| HumanGovernanceError::Store)?;
                    let tree = repositories
                        .worktrees
                        .get(&id)
                        .ok_or(HumanGovernanceError::Store)?;
                    if query.parent.is_some_and(|parent| {
                        parent
                            != ScopeBoundary::Repository {
                                repository_id: tree.repository_instance_id,
                            }
                    }) {
                        last = Some(row.row_id.clone());
                        continue;
                    }
                    let mut restrictions = repo_restrictions(
                        repositories.repositories.get(&tree.repository_instance_id),
                    );
                    if tree.lifecycle != WorktreeLifecycle::Active {
                        restrictions.push(Restriction::WorktreeNotActive)
                    }
                    ScopeDirectoryEntry {
                        stable_key: row.row_id.clone(),
                        selection: Selection::Worktree { worktree_id: id },
                        label: tree
                            .current_path
                            .as_deref()
                            .map(path_label)
                            .unwrap_or_else(|| format!("工作树 {}", id)),
                        title_state: ScopeTitleState::Metadata,
                        path_hint: tree.current_path.clone(),
                        branch_hint: tree
                            .current_snapshot_id
                            .and_then(|id| repositories.snapshots.get(&id))
                            .and_then(|snapshot| snapshot.branch_ref.clone()),
                        lifecycle: Some(
                            match tree.lifecycle {
                                WorktreeLifecycle::Active => "active",
                                WorktreeLifecycle::Missing => "missing",
                                WorktreeLifecycle::Removed => "removed",
                                WorktreeLifecycle::Pruned => "pruned",
                                WorktreeLifecycle::Archived => "archived",
                            }
                            .into(),
                        ),
                        restrictions,
                        has_children: tasks.values().any(|(task, _)| {
                            task_in(task, ScopeBoundary::Worktree { worktree_id: id })
                        }),
                    }
                }
                Some("task") => {
                    let id = row
                        .object_id
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?
                        .parse()
                        .map_err(|_| HumanGovernanceError::Store)?;
                    let (task, _) = tasks.get(&id).ok_or(HumanGovernanceError::Store)?;
                    if query.parent.is_some_and(|parent| !task_in(task, parent)) {
                        last = Some(row.row_id.clone());
                        continue;
                    }
                    let mut entry = ScopeDirectoryEntry {
                        stable_key: row.row_id.clone(),
                        selection: Selection::Task { task_id: id },
                        label: format!("任务 {}", id),
                        title_state: ScopeTitleState::Unavailable,
                        path_hint: None,
                        branch_hint: None,
                        lifecycle: Some(task.lifecycle.as_str().into()),
                        restrictions: vec![Restriction::CurrentAccessNotEvaluated],
                        has_children: false,
                    };
                    if index.is_none() {
                        index = Some(export::presentation_index(&snapshot, deadline));
                    }
                    if let Some(Ok(index)) = &index {
                        // A task title is source-derived content. Unknown roots must
                        // not become a title/name-search side channel.
                        let mut source_rows = vec![row];
                        let roots_resolved = task.request_root_refs.iter().all(|reference| {
                            let before = source_rows.len();
                            if let Some(rows) = index.get(reference.as_str()) {
                                source_rows.extend(rows.iter().copied().filter(|source| {
                                    matches!(
                                        source.object_kind.as_deref(),
                                        Some(
                                            "source_receipt"
                                                | "source_observation"
                                                | "evidence_surface"
                                        )
                                    )
                                }));
                            }
                            source_rows.len() > before
                        });
                        if roots_resolved {
                            match self
                                .readable_source_rows(&snapshot, &source_rows, deadline)
                                .await
                            {
                                Ok(()) => {
                                    let label = display_name(&task.canonical_goal);
                                    if !label.is_empty() {
                                        entry.label = label;
                                        entry.title_state = ScopeTitleState::ContentReady;
                                    }
                                }
                                Err(export::Failure::Denied) => {
                                    entry.title_state = ScopeTitleState::AccessDenied
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    entry
                }
                _ => unreachable!(),
            };
            if matches!(
                entry.title_state,
                ScopeTitleState::AccessDenied | ScopeTitleState::Unavailable
            ) {
                page.names_complete = false;
            }
            // Match the authorized canonical name, not just its bounded label.
            if !needle.is_empty()
                && !entry.label.to_lowercase().contains(&needle)
                && !entry
                    .path_hint
                    .as_ref()
                    .is_some_and(|value| value.to_lowercase().contains(&needle))
                && !entry
                    .branch_hint
                    .as_ref()
                    .is_some_and(|value| value.to_lowercase().contains(&needle))
            {
                last = Some(row.row_id.clone());
                continue;
            }
            if page.items.len() == usize::from(limit) {
                page.next_cursor = directory_cursor(snapshot.frontier, &query, last.as_deref())?;
                break;
            }
            entry.label = entry.label.chars().take(160).collect();
            entry.restrictions.sort();
            entry.restrictions.dedup();
            last = Some(row.row_id.clone());
            page.items.push(entry);
        }
        Ok(Ok(page))
    }
}

fn directory_cursor(
    frontier: u64,
    query: &ScopeDirectoryQuery,
    after_key: Option<&str>,
) -> Result<Option<String>, HumanGovernanceError> {
    after_key
        .map(|key| {
            serde_json::to_string(&ScopeDirectoryCursor {
                frontier,
                query: query.clone(),
                after_key: key.into(),
            })
            .map_err(|_| HumanGovernanceError::Store)
        })
        .transpose()
}
fn task_in(task: &Task, parent: ScopeBoundary) -> bool {
    task.scope_memberships
        .iter()
        .any(|membership| match parent {
            ScopeBoundary::Repository { repository_id } => {
                membership.repository_instance_id == Some(repository_id)
            }
            ScopeBoundary::Worktree { worktree_id } => {
                membership.worktree_instance_ids.contains(&worktree_id)
            }
            ScopeBoundary::Task { .. } => false,
        })
}
fn display_name(value: &str) -> String {
    value
        .split(|ch: char| ch.is_whitespace() || ch.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
fn path_label(path: &str) -> String {
    let label = display_name(
        std::path::Path::new(path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(path),
    );
    if label.is_empty() {
        display_name(path)
    } else {
        label
    }
}
fn repo_restrictions(repo: Option<&RepositoryInstance>) -> Vec<Restriction> {
    let mut restrictions = vec![Restriction::CurrentAccessNotEvaluated];
    if let Some(repo) = repo {
        if repo.user_disabled {
            restrictions.push(Restriction::UserDisabled)
        }
        if repo
            .capability_state
            .as_ref()
            .is_some_and(|state| state.trust_revoked)
        {
            restrictions.push(Restriction::TrustRevoked)
        }
    }
    restrictions
}
