//! Published compiler references and current access facts, never bodies or presentation summaries.
use super::*;
use crate::WriterActorError;
use evertrace_domain::query::{
    CompiledProjectionPage, CompiledProjectionQuery, CompiledSourceMetadata, ReadDataIdentity,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    query: CompiledProjectionQuery,
    frontier: u64,
    data_identity: ReadDataIdentity,
    position: Position,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Position {
    Directory { key: String },
    Entries { offset: u64 },
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
    data_identity: ReadDataIdentity,
    position: Option<Position>,
) -> Result<Option<String>, HumanGovernanceError> {
    position
        .map(|position| {
            serde_json::to_string(&Cursor {
                query: query.clone(),
                frontier,
                data_identity,
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
    ) -> Result<Result<CompiledProjectionPage, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if limit == 0
            || limit > 64
            || matches!(query, CompiledProjectionQuery::Entries { .. }) && limit > 8
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let state =
            crate::EngineService::read_state(self.writer.read_handle(), self.effective_config_hash)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
        let position = if let Some(after) = after {
            if after.len() > 4096 {
                return Err(HumanGovernanceError::InvalidInput);
            }
            let value: Cursor =
                serde_json::from_str(after).map_err(|_| HumanGovernanceError::InvalidInput)?;
            if value.query != query || expected_frontier != Some(value.frontier) {
                return Err(HumanGovernanceError::InvalidInput);
            }
            if value.data_identity != state.data_identity {
                return Ok(Err(state.frontier));
            }
            Some(value.position)
        } else {
            None
        };
        let result = match &query {
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
                    state.data_identity,
                    context.next_key.map(|key| Position::Directory { key }),
                )?;
                Ok(Ok(CompiledProjectionPage::Directory {
                    frontier: context.frontier,
                    data_identity: state.data_identity,
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
                self.compiled_entries_page(query, context, state.data_identity)
                    .await
            }
        };
        let current =
            crate::EngineService::read_state(self.writer.read_handle(), self.effective_config_hash)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
        if current.frontier != state.frontier || current.data_identity != state.data_identity {
            return Ok(Err(current.frontier));
        }
        result
    }

    async fn compiled_entries_page(
        &self,
        query: CompiledProjectionQuery,
        context: evertrace_store::projections::CompiledEntriesContext,
        data_identity: ReadDataIdentity,
    ) -> Result<Result<CompiledProjectionPage, u64>, HumanGovernanceError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut entries = Vec::new();
        for source in context.sources {
            let mut entry = CompiledSourceMetadata {
                revision_ref: source.revision,
                contextual: source.contextual,
                membership_revision: source.membership_revision,
                object_kind: source.object_kind.into(),
                state: HumanContentState::Ready,
            };
            for reference in entry
                .membership_revision
                .iter()
                .chain([&entry.revision_ref])
            {
                let state = self
                    .compiled_source_access(reference, context.frontier, data_identity, deadline)
                    .await;
                if state != HumanContentState::Ready {
                    entry.state = state;
                    break;
                }
            }
            entries.push(entry);
        }
        let title_readable = entries.iter().any(|entry| {
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
            data_identity,
            context
                .next_offset
                .map(|offset| Position::Entries { offset }),
        )?;
        Ok(Ok(CompiledProjectionPage::Entries {
            frontier: context.frontier,
            data_identity,
            query,
            metadata: context.metadata,
            title: title_readable.then_some(context.title).flatten(),
            state,
            scope_available: context.scope_available,
            complete,
            matching_count: context.matching_count,
            entries,
            next_cursor,
        }))
    }

    async fn compiled_source_access(
        &self,
        revision: &RevisionId,
        frontier: u64,
        data_identity: ReadDataIdentity,
        deadline: std::time::Instant,
    ) -> HumanContentState {
        use evertrace_domain::query::{ExactRecordQuery, ExactRecordRef, MetadataReadOutcome};
        let query = ExactRecordQuery {
            reference: ExactRecordRef {
                stable_key: revision.to_string(),
                revision_ref: Some(revision.to_string()),
            },
            field: None,
            range: None,
            expected_data_identity: Some(data_identity),
            expected_selection: None,
        };
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            crate::EngineService::read_exact_record(
                self.writer.clone(),
                Box::new(query),
                self.effective_config_hash,
                self.session_report.clone().unwrap_or_default(),
                self.runtime_snapshot
                    .as_ref()
                    .map(|value| value.cas_dir.clone())
                    .unwrap_or_default(),
            ),
        )
        .await;
        match result {
            Ok(Ok(MetadataReadOutcome::Page(page))) if page.state.frontier == frontier => {
                page.content_state
            }
            _ => HumanContentState::Unavailable,
        }
    }
}
