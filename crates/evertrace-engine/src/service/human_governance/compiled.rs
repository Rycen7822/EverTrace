//! Read existing compiler output and exact source values; never rebuild or generate.
use super::*;
use crate::WriterActorError;
use evertrace_domain::query::{CompiledProjectionMetadata, CompiledProjectionQuery};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    query: CompiledProjectionQuery,
    frontier: u64,
    position: Position,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Position {
    Directory { key: String },
    Entries { offset: u64 },
}

pub struct HumanCompiledEntry {
    pub reference: String,
    pub revision_ref: String,
    pub contextual: bool,
    pub membership_revision: Option<String>,
    pub state: HumanContentState,
    pub item: Option<HumanSummary>,
}

pub enum HumanCompiledPage {
    Directory {
        frontier: u64,
        query: CompiledProjectionQuery,
        items: Vec<CompiledProjectionMetadata>,
        scope_available: bool,
        complete: bool,
        matching_count: Option<u64>,
        next_cursor: Option<String>,
    },
    Entries {
        frontier: u64,
        query: CompiledProjectionQuery,
        metadata: Option<CompiledProjectionMetadata>,
        title: Option<String>,
        state: HumanContentState,
        scope_available: bool,
        complete: bool,
        matching_count: Option<u64>,
        entries: Vec<HumanCompiledEntry>,
        next_cursor: Option<String>,
    },
}

fn actor_error(error: WriterActorError) -> HumanGovernanceError {
    match error {
        WriterActorError::InvalidInput => HumanGovernanceError::InvalidInput,
        _ => HumanGovernanceError::Store,
    }
}

fn cursor(
    query: &CompiledProjectionQuery,
    frontier: u64,
    position: Option<Position>,
) -> Result<Option<String>, HumanGovernanceError> {
    position
        .map(|position| {
            serde_json::to_string(&Cursor {
                query: query.clone(),
                frontier,
                position,
            })
            .map_err(|_| HumanGovernanceError::Store)
        })
        .transpose()
}

impl HumanGovernanceService {
    pub async fn compiled_projections(
        &self,
        query: CompiledProjectionQuery,
        expected_frontier: Option<u64>,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<HumanCompiledPage, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if limit == 0
            || limit > 64
            || matches!(query, CompiledProjectionQuery::Entries { .. }) && limit > 8
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let position = if let Some(after) = after {
            if after.len() > 4096 {
                return Err(HumanGovernanceError::InvalidInput);
            }
            let value: Cursor =
                serde_json::from_str(after).map_err(|_| HumanGovernanceError::InvalidInput)?;
            if value.query != query || expected_frontier != Some(value.frontier) {
                return Err(HumanGovernanceError::InvalidInput);
            }
            Some(value.position)
        } else {
            None
        };
        match &query {
            CompiledProjectionQuery::Directory { .. } => {
                let key = match position {
                    Some(Position::Directory { key }) => Some(key),
                    None => None,
                    _ => return Err(HumanGovernanceError::InvalidInput),
                };
                let context = self
                    .writer
                    .compiled_directory_context(&query, key, usize::from(limit))
                    .await
                    .map_err(actor_error)?;
                if expected_frontier.is_some_and(|frontier| frontier != context.frontier) {
                    return Ok(Err(context.frontier));
                }
                let next_cursor = cursor(
                    &query,
                    context.frontier,
                    context.next_key.map(|key| Position::Directory { key }),
                )?;
                Ok(Ok(HumanCompiledPage::Directory {
                    frontier: context.frontier,
                    query,
                    items: context.items,
                    scope_available: context.scope_available,
                    complete: context.complete,
                    matching_count: context.matching_count,
                    next_cursor,
                }))
            }
            CompiledProjectionQuery::Entries { .. } => {
                let Some(frontier) = expected_frontier else {
                    return Err(HumanGovernanceError::InvalidInput);
                };
                let offset = match position {
                    Some(Position::Entries { offset }) => offset,
                    None => 0,
                    _ => return Err(HumanGovernanceError::InvalidInput),
                };
                let context = self
                    .writer
                    .compiled_entries_context(&query, offset, usize::from(limit))
                    .await
                    .map_err(actor_error)?;
                if frontier != context.frontier {
                    return Ok(Err(context.frontier));
                }
                self.compiled_entries_page(query, context).await
            }
        }
    }

    async fn compiled_entries_page(
        &self,
        query: CompiledProjectionQuery,
        context: evertrace_store::projections::CompiledEntriesContext,
    ) -> Result<Result<HumanCompiledPage, u64>, HumanGovernanceError> {
        let snapshot = if context.sources.is_empty() {
            None
        } else {
            let snapshot = self.writer.project_objects().await.map_err(actor_error)?;
            if snapshot.frontier != context.frontier {
                return Ok(Err(snapshot.frontier));
            }
            Some(snapshot)
        };
        let deadline = std::time::Instant::now() + presentation::READ_DEADLINE;
        let index = snapshot
            .as_ref()
            .map(|snapshot| export::presentation_index(snapshot, deadline))
            .transpose();
        let mut entries = Vec::new();
        for source in context.sources {
            let mut entry = HumanCompiledEntry {
                reference: source.revision.to_string(),
                revision_ref: source.revision.to_string(),
                contextual: source.contextual,
                membership_revision: source.membership_revision.map(|id| id.to_string()),
                state: HumanContentState::Unavailable,
                item: None,
            };
            if let (Some(snapshot), Ok(Some(index))) = (&snapshot, &index) {
                let row = index.get(entry.reference.as_str()).and_then(|rows| {
                    rows.iter()
                        .copied()
                        .filter(|row| row.object_kind.as_deref() == Some(source.object_kind))
                        .filter(|row| {
                            row.current_revision_id.as_deref() == Some(entry.revision_ref.as_str())
                        })
                        .min_by_key(|row| row.row_class != Some(ObjectRowClass::Object))
                });
                if let Some(row) = row {
                    let gate_row = match entry.membership_revision.as_deref() {
                        Some(revision) => index.get(revision).and_then(|rows| {
                            rows.iter()
                                .copied()
                                .find(|row| row.object_kind.as_deref() == Some("core_membership"))
                        }),
                        None => Some(row),
                    };
                    if let Some(gate_row) = gate_row {
                        match self
                            .readable_indexed_row(snapshot, gate_row, index, deadline)
                            .await
                        {
                            Ok(()) => {
                                let mut item = summary_fields(row, HumanSurface::Explorer);
                                let detail = presentation::present(row)?;
                                entry.state = detail.state;
                                item.semantic_detail = Some(detail);
                                entry.item = Some(item);
                            }
                            Err(export::Failure::Denied) => {
                                entry.state = HumanContentState::AccessDenied
                            }
                            Err(_) => {}
                        }
                    } else {
                        entry.state = HumanContentState::Missing;
                    }
                } else {
                    entry.state = HumanContentState::Missing;
                }
            }
            entries.push(entry);
        }
        let body_read = entries.iter().any(|entry| {
            !entry.contextual
                && matches!(
                    entry.state,
                    HumanContentState::Ready | HumanContentState::TooLarge
                )
        });
        let complete = context.complete
            && entries.iter().all(|entry| {
                matches!(
                    entry.state,
                    HumanContentState::Ready | HumanContentState::TooLarge
                )
            });
        let state = if context.metadata.is_none() {
            HumanContentState::Missing
        } else if !context.scope_available || !context.complete && entries.is_empty() {
            HumanContentState::Unavailable
        } else {
            HumanContentState::Ready
        };
        let next_cursor = cursor(
            &query,
            context.frontier,
            context
                .next_offset
                .map(|offset| Position::Entries { offset }),
        )?;
        Ok(Ok(HumanCompiledPage::Entries {
            frontier: context.frontier,
            query,
            metadata: context.metadata,
            title: body_read.then_some(context.title).flatten(),
            state,
            scope_available: context.scope_available,
            complete,
            matching_count: context.matching_count,
            entries,
            next_cursor,
        }))
    }
}
