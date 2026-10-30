//! Request-local human directory over current typed identities; no discovery scan.
use super::{
    HumanGovernanceError, HumanGovernanceService, export, presentation, presentation::display_name,
};
use evertrace_domain::{
    query::{
        MemoryScopeSelection as Selection, ScopeDirectoryCursor, ScopeDirectoryEntry,
        ScopeDirectoryPage, ScopeDirectoryQuery, ScopeReadRestriction as Restriction,
        ScopeTitleState,
    },
    repository::{RepositoryInstance, WorktreeLifecycle},
};
use evertrace_store::JournalPayload;
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
        let deadline = Instant::now() + presentation::READ_DEADLINE;
        let mut last = cursor.as_ref().map(|value| value.after_key.clone());
        let needle = query.name.to_lowercase();
        let mut context = self
            .writer
            .scope_directory_context(&query, last.as_deref(), deadline)
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if expected_frontier.is_some_and(|value| value != context.frontier) {
            return Ok(Err(context.frontier));
        }
        let mut page = ScopeDirectoryPage {
            frontier: context.frontier,
            query: query.clone(),
            parent_available: context.parent_available,
            complete: context.parent_available,
            names_complete: context.parent_available,
            items: Vec::new(),
            next_cursor: None,
        };
        if !page.parent_available {
            return Ok(Ok(page));
        }
        loop {
            for candidate in &context.items {
                let row = &candidate.row;
                if Instant::now() >= deadline {
                    page.complete = false;
                    page.names_complete = false;
                    page.next_cursor = directory_cursor(page.frontier, &query, last.as_deref())?;
                    return Ok(Ok(page));
                }
                let payload: JournalPayload = serde_json::from_str(
                    row.payload_json
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
                let mut entry =
                    match payload {
                        JournalPayload::RepositoryInstanceRecorded(repo) => ScopeDirectoryEntry {
                            stable_key: row.row_id.clone(),
                            selection: Selection::Repository {
                                repository_id: repo.repository_id,
                            },
                            label: path_label(&repo.current_path),
                            title_state: ScopeTitleState::Metadata,
                            path_hint: Some(repo.current_path.clone()),
                            branch_hint: None,
                            lifecycle: None,
                            restrictions: repo_restrictions(Some(&repo)),
                            has_children: candidate.has_children,
                        },
                        JournalPayload::WorktreeInstanceRecorded(tree) => {
                            let mut restrictions = repo_restrictions(candidate.repository.as_ref());
                            if tree.lifecycle != WorktreeLifecycle::Active {
                                restrictions.push(Restriction::WorktreeNotActive);
                            }
                            ScopeDirectoryEntry {
                                stable_key: row.row_id.clone(),
                                selection: Selection::Worktree {
                                    worktree_id: tree.worktree_instance_id,
                                },
                                label: tree.current_path.as_deref().map(path_label).unwrap_or_else(
                                    || format!("工作树 {}", tree.worktree_instance_id),
                                ),
                                title_state: ScopeTitleState::Metadata,
                                path_hint: tree.current_path.clone(),
                                branch_hint: candidate.branch_ref.clone(),
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
                                has_children: candidate.has_children,
                            }
                        }
                        JournalPayload::TaskRecorded(task) => {
                            let mut entry = ScopeDirectoryEntry {
                                stable_key: row.row_id.clone(),
                                selection: Selection::Task {
                                    task_id: task.task_id,
                                },
                                label: format!("任务 {}", task.task_id),
                                title_state: ScopeTitleState::Unavailable,
                                path_hint: None,
                                branch_hint: None,
                                lifecycle: Some(task.lifecycle.as_str().into()),
                                restrictions: vec![Restriction::CurrentAccessNotEvaluated],
                                has_children: false,
                            };
                            if candidate.sources_complete {
                                // The native Capture owner supplies a complete direct source
                                // cohort plus its scope/suppression facts. No partial snapshot
                                // or export dependency graph stands in for that context.
                                let mut all = BTreeMap::new();
                                let mut selected = BTreeMap::new();
                                all.insert(row.row_id.clone(), row.clone());
                                selected.insert(row.row_id.clone(), ());
                                for source_row in &candidate.source_rows {
                                    selected.insert(source_row.row_id.clone(), ());
                                    all.insert(source_row.row_id.clone(), source_row.clone());
                                }
                                for scope in &candidate.source_scope_rows {
                                    all.insert(scope.row_id.clone(), scope.clone());
                                }
                                let all = all.into_values().collect::<Vec<_>>();
                                let selected = all
                                    .iter()
                                    .filter(|row| selected.contains_key(&row.row_id))
                                    .collect::<Vec<_>>();
                                match self
                                    .readable_directory_sources(
                                        &all,
                                        &selected,
                                        candidate.source_suppressed,
                                        deadline,
                                    )
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
                            entry
                        }
                        _ => return Err(HumanGovernanceError::Store),
                    };
                if matches!(
                    entry.title_state,
                    ScopeTitleState::AccessDenied | ScopeTitleState::Unavailable
                ) {
                    page.names_complete = false;
                }
                if !needle.is_empty()
                    && !entry.label.to_lowercase().contains(&needle)
                    && !entry
                        .path_hint
                        .as_ref()
                        .is_some_and(|v| v.to_lowercase().contains(&needle))
                    && !entry
                        .branch_hint
                        .as_ref()
                        .is_some_and(|v| v.to_lowercase().contains(&needle))
                {
                    last = Some(row.row_id.clone());
                    continue;
                }
                if page.items.len() == usize::from(limit) {
                    page.next_cursor = directory_cursor(page.frontier, &query, last.as_deref())?;
                    return Ok(Ok(page));
                }
                entry.label = entry.label.chars().take(160).collect();
                entry.restrictions.sort();
                entry.restrictions.dedup();
                last = Some(row.row_id.clone());
                page.items.push(entry);
            }
            if !context.complete || Instant::now() >= deadline {
                page.complete = false;
                page.names_complete = false;
                page.next_cursor = directory_cursor(page.frontier, &query, last.as_deref())?;
                return Ok(Ok(page));
            }
            let Some(after) = context.next_cursor else {
                return Ok(Ok(page));
            };
            context = self
                .writer
                .scope_directory_context(&query, Some(&after), deadline)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            if context.frontier != page.frontier {
                return Ok(Err(context.frontier));
            }
        }
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
