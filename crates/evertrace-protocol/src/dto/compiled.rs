use super::*;
use evertrace_domain::query::{
    CompiledProjectionKind, CompiledProjectionMetadata, CompiledProjectionQuery,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanCompiledEntry {
    pub reference: String,
    pub revision_ref: String,
    pub contextual: bool,
    pub membership_revision: Option<String>,
    pub state: HumanContentState,
    pub item: Option<Box<HumanSnapshotItem>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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

fn valid_metadata(value: &CompiledProjectionMetadata, frontier: u64) -> bool {
    CompiledProjectionQuery::Entries {
        reference: value.reference.clone(),
        selection: evertrace_domain::query::MemoryScopeSelection::All,
        include_global: false,
    }
    .validate()
    .is_ok()
        && value.source_watermark <= frontier
        && match value.kind {
            CompiledProjectionKind::Wiki => {
                value.reference.starts_with("projection:wiki:")
                    && value.compiler_version.is_some_and(|v| v > 0)
                    && value.render_identity.is_some()
            }
            CompiledProjectionKind::Core => {
                value.reference.starts_with("projection:core:")
                    && value.compiler_version.is_none()
                    && value.render_identity.is_none()
            }
        }
}

impl HumanCompiledPage {
    pub fn validate(&self) -> bool {
        match self {
            Self::Directory {
                frontier,
                query,
                items,
                scope_available,
                complete,
                matching_count,
                next_cursor,
            } => {
                let CompiledProjectionQuery::Directory { projection, .. } = query else {
                    return false;
                };
                query.validate().is_ok()
                    && items.len() <= 64
                    && (!complete || *scope_available)
                    && items
                        .iter()
                        .all(|v| valid_metadata(v, *frontier) && v.kind == *projection)
                    && items.windows(2).all(|v| v[0].reference < v[1].reference)
                    && matching_count.is_none_or(|count| count >= items.len() as u64)
                    && next_cursor
                        .as_ref()
                        .is_none_or(|v| !v.is_empty() && v.len() <= 4096)
                    && (*scope_available
                        || items.is_empty() && matching_count.is_none() && next_cursor.is_none())
            }
            Self::Entries {
                frontier,
                query,
                metadata,
                title,
                state,
                scope_available,
                complete,
                matching_count,
                entries,
                next_cursor,
            } => {
                let CompiledProjectionQuery::Entries { reference, .. } = query else {
                    return false;
                };
                query.validate().is_ok()
                    && entries.len() <= 8
                    && (!complete || *scope_available)
                    && metadata
                        .as_ref()
                        .is_none_or(|v| valid_metadata(v, *frontier) && v.reference == *reference)
                    && (metadata.is_some()
                        || *state == HumanContentState::Missing && entries.is_empty())
                    && title.as_ref().is_none_or(|v| {
                        metadata
                            .as_ref()
                            .is_some_and(|v| v.kind == CompiledProjectionKind::Wiki)
                            && !v.is_empty()
                            && v.len() <= 4096
                            && entries.iter().any(|v| {
                                !v.contextual
                                    && matches!(
                                        v.state,
                                        HumanContentState::Ready | HumanContentState::TooLarge
                                    )
                            })
                    })
                    && entries.iter().all(|entry| {
                        entry.revision_ref.parse::<RevisionId>().is_ok()
                            && entry.reference == entry.revision_ref
                            && metadata.as_ref().is_some_and(|meta| match meta.kind {
                                CompiledProjectionKind::Wiki => entry.membership_revision.is_none(),
                                CompiledProjectionKind::Core => {
                                    !entry.contextual && entry.membership_revision.is_some()
                                }
                            })
                            && (!complete
                                || matches!(
                                    entry.state,
                                    HumanContentState::Ready | HumanContentState::TooLarge
                                ))
                            && entry
                                .membership_revision
                                .as_ref()
                                .is_none_or(|v| v.parse::<RevisionId>().is_ok())
                            && entry.item.as_ref().is_none_or(|item| {
                                item.validate()
                                    && item.source_event_seq <= *frontier
                                    && item.object_kind
                                        == if entry.contextual {
                                            "work_episode"
                                        } else {
                                            "atom_revision"
                                        }
                                    && item.revision_ref.as_deref()
                                        == Some(entry.revision_ref.as_str())
                                    && item
                                        .semantic_detail
                                        .as_ref()
                                        .is_none_or(|v| v.state == entry.state)
                            })
                            && match entry.state {
                                HumanContentState::Ready | HumanContentState::TooLarge => {
                                    entry.item.as_ref().is_some_and(|item| {
                                        item.semantic_detail
                                            .as_ref()
                                            .is_some_and(|v| v.state == entry.state)
                                    })
                                }
                                _ => entry.item.is_none(),
                            }
                    })
                    && matching_count.is_none_or(|count| count >= entries.len() as u64)
                    && next_cursor
                        .as_ref()
                        .is_none_or(|v| !v.is_empty() && v.len() <= 4096)
                    && (*scope_available
                        || entries.is_empty() && matching_count.is_none() && title.is_none())
            }
        }
    }
}
