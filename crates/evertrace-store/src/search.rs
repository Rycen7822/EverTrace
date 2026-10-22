use evertrace_domain::evidence::{
    EvidenceError, EvidenceSurface, InstructionAuthority, SourceArchiveMode, SourceObservation,
    SourceReceipt, UnsupportedRecordClassification, evidence_span_hash, hex,
};
use std::sync::Arc;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    str::FromStr,
};

use arrow_array::{
    Array, ArrayRef, Float32Array, Int64Array, RecordBatch, StringArray, UInt64Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use lancedb::{
    Table,
    index::scalar::FullTextSearchQuery,
    query::{ExecutableQuery, HasQuery, QueryBase, Select},
};

use crate::{StoreError, connection::StoreReadHandle};

pub const SEARCH_TABLE: &str = "evertrace_search";
pub const SEARCH_CHECKPOINT_ID: &str = "checkpoint:evertrace_search";
pub const SEARCH_PROJECTION_GENERATION: u64 = 1;

#[derive(Clone)]
pub struct SearchIndex {
    data_dir: PathBuf,
    readers: StoreReadHandle,
}

pub struct SearchSnapshot {
    table: Table,
    frontier: u64,
    authoritative_frontier: u64,
    // Declared last so the pinned table drops before the read fence and permit.
    _lease: crate::connection::StoreReadLease,
}

#[derive(Clone, Debug, Default)]
pub struct SearchHardFilter {
    /// Current publication eligibility, separate from deletion suppression.
    pub procedure_revisions: Option<BTreeSet<String>>,
    pub method_proposal_revisions: BTreeSet<String>,
    pub task_id: Option<String>,
    pub repository_id: Option<String>,
    pub worktree_id: Option<String>,
    pub source_kind: Option<String>,
    pub source_role: Option<String>,
    pub authority: Option<String>,
    pub lifecycle: Option<String>,
    pub object_only: bool,
    pub current_only: bool,
    pub suppressed_hashes: BTreeSet<String>,
    pub suppressed_refs: BTreeSet<String>,
    pub event_time_as_of: Option<i64>,
    pub event_time_interval: Option<(i64, i64)>,
    pub source_sequence_at_most: Option<u64>,
}

impl SearchIndex {
    /// Standalone read-only opener: validate the real on-disk store, attach a
    /// native connection to the same binding and open the search table.
    pub async fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let readers = StoreReadHandle::open_read_only(data_dir).await?;
        let connection = crate::connection::connect_native(data_dir).await?;
        readers.bind_read_only_search(connection)?;
        Self::from_read_handle(data_dir, readers).await
    }

    /// Share the writer's single Lance search lifecycle and read fence. The
    /// writer publishes its validated binding; a handle without one fails
    /// closed instead of opening a private connection from the path.
    pub async fn open_with_read_handle(
        data_dir: &Path,
        readers: StoreReadHandle,
    ) -> Result<Self, StoreError> {
        Self::from_read_handle(data_dir, readers).await
    }

    async fn from_read_handle(
        data_dir: &Path,
        readers: StoreReadHandle,
    ) -> Result<Self, StoreError> {
        let lease = readers.search_lease().await?;
        let table = lease
            .lance()
            .open_table(SEARCH_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        read_search_rows(&table).await?;
        let indices = table
            .list_indices()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        if indices.len() != 1 || indices[0].columns != ["text"] {
            return Err(StoreError::StoreCorrupt);
        }
        drop(table);
        drop(lease);
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            readers,
        })
    }

    pub fn read_handle(&self) -> StoreReadHandle {
        self.readers.clone()
    }

    pub async fn all(&self) -> Result<Vec<SearchProjectionRow>, StoreError> {
        let snapshot = self.snapshot().await?;
        read_search_rows(&snapshot.table).await
    }

    pub async fn fts(&self, query: &str) -> Result<Vec<SearchProjectionRow>, StoreError> {
        self.snapshot()
            .await?
            .fts(query, &SearchHardFilter::default(), 256)
            .await
    }

    pub async fn snapshot(&self) -> Result<SearchSnapshot, StoreError> {
        self.snapshot_validated(None).await
    }

    /// Use a frontier freshly validated by the caller's current projection.
    ///
    /// The post-pin journal read remains authoritative. A mismatch falls back
    /// to the ordinary bounded before/pin/after validation rather than trusting
    /// the supplied value as a cache.
    pub async fn snapshot_after_validated_frontier(
        &self,
        validated_frontier: u64,
    ) -> Result<SearchSnapshot, StoreError> {
        self.snapshot_validated(Some(validated_frontier)).await
    }

    async fn snapshot_validated(
        &self,
        validated_frontier: Option<u64>,
    ) -> Result<SearchSnapshot, StoreError> {
        for attempt in 0..2 {
            // The snapshot holds the fence and Lance connection. SQL frontier
            // reads take a permit only for their actual blocking lifetime.
            let lease = self.readers.search_lease().await?;
            let before = self.authoritative_frontier(&lease).await?;
            let (table, frontier) = self.pinned_snapshot(&lease).await?;
            let after = self.authoritative_frontier(&lease).await?;
            if before == after || after == validated_frontier.unwrap_or(u64::MAX) || attempt == 1 {
                if frontier > after {
                    return Err(StoreError::StoreCorrupt);
                }
                return Ok(SearchSnapshot {
                    table,
                    frontier,
                    authoritative_frontier: after,
                    _lease: lease,
                });
            }
        }
        unreachable!("bounded snapshot loop always returns")
    }

    async fn pinned_snapshot(
        &self,
        lease: &crate::connection::StoreReadLease,
    ) -> Result<(Table, u64), StoreError> {
        evertrace_capture::ConfinedRoot::open_owned_private(&crate::connection::native_root(
            &self.data_dir,
        ))
        .map_err(|_| StoreError::StoreCorrupt)?;
        let table = lease
            .lance()
            .open_table(SEARCH_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        table
            .checkout_latest()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let version = table.version().await.map_err(|_| StoreError::LanceDb)?;
        table
            .checkout(version)
            .await
            .map_err(|_| StoreError::LanceDb)?;
        if table
            .schema()
            .await
            .map_err(|_| StoreError::LanceDb)?
            .as_ref()
            != search_schema().as_ref()
        {
            return Err(StoreError::StoreCorrupt);
        }
        let checkpoints = query_rows(
            &table,
            Some(format!("row_id = '{}'", SEARCH_CHECKPOINT_ID)),
            2,
            None,
        )
        .await?;
        let frontier = exact_checkpoint_frontier(&checkpoints)?;
        Ok((table, frontier))
    }

    async fn authoritative_frontier(
        &self,
        lease: &crate::connection::StoreReadLease,
    ) -> Result<u64, StoreError> {
        evertrace_capture::ConfinedRoot::open_owned_private(&crate::connection::native_root(
            &self.data_dir,
        ))
        .map_err(|_| StoreError::StoreCorrupt)?;
        self.readers
            .lease_read(lease, |connection, _| {
                crate::sqlite_state::read_persisted_frontier(connection)
            })
            .await
    }
}

fn exact_checkpoint_frontier(rows: &[SearchProjectionRow]) -> Result<u64, StoreError> {
    let [checkpoint] = rows else {
        return Err(StoreError::StoreCorrupt);
    };
    if checkpoint.row_id != SEARCH_CHECKPOINT_ID || checkpoint.row_variant != "checkpoint" {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(checkpoint.source_event_seq)
}

impl SearchSnapshot {
    pub const fn frontier(&self) -> u64 {
        self.frontier
    }

    pub const fn authoritative_frontier(&self) -> u64 {
        self.authoritative_frontier
    }

    pub async fn structured(
        &self,
        identifiers: &[String],
        filter: &SearchHardFilter,
        limit: usize,
    ) -> Result<Vec<SearchProjectionRow>, StoreError> {
        if identifiers.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let exact = identifiers
            .iter()
            .flat_map(|value| {
                let value = sql_literal(value);
                [
                    format!("candidate_id = {value}"),
                    format!("source_ref = {value}"),
                ]
            })
            .collect::<Vec<_>>()
            .join(" OR ");
        let filter = combine_filter(filter_sql(filter), Some(format!("({exact})")));
        query_rows(&self.table, filter, limit, None).await
    }

    pub async fn fts(
        &self,
        query: &str,
        filter: &SearchHardFilter,
        limit: usize,
    ) -> Result<Vec<SearchProjectionRow>, StoreError> {
        if query.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        query_rows(&self.table, filter_sql(filter), limit, Some(query)).await
    }

    /// The passive MCP read has no Work anchor: its typed, session-bound
    /// candidate window must constrain FTS before LIMIT, never search globally.
    pub async fn fts_selected(
        &self,
        query: &str,
        identifiers: &[String],
        limit: usize,
    ) -> Result<Vec<SearchProjectionRow>, StoreError> {
        if identifiers.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        if query.is_empty() || identifiers.len() > 32 || limit > 32 {
            return Err(StoreError::InvalidInput);
        }
        let selected = format!(
            "candidate_id IN ({})",
            identifiers
                .iter()
                .map(|id| sql_literal(id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let filter = combine_filter(
            filter_sql(&SearchHardFilter {
                object_only: true,
                current_only: true,
                ..Default::default()
            }),
            Some(selected),
        );
        query_rows(&self.table, filter, limit, Some(query)).await
    }
}

/// Physical row address system column exposed by the pinned Lance scanner.
const ROW_ADDR: &str = "_rowaddr";

const SEARCH_COLUMNS: [&str; 26] = [
    "row_id",
    "row_variant",
    "candidate_id",
    "source_ref",
    "source_kind",
    "text",
    "source_role",
    "content_trust",
    "capture_completeness",
    "instruction_authority",
    "object_kind",
    "currentness",
    "lifecycle",
    "epistemic",
    "authority",
    "task_id",
    "repository_id",
    "worktree_id",
    "event_time_us",
    "recorded_at_us",
    "source_sequence",
    "time_domain",
    "retrieval_completeness",
    "suppression_ref_hash",
    "source_event_seq",
    "projection_generation",
];

/// Test-only bridge to the production FTS query path (`query_rows`): the same
/// indexed-plus-flat selection and row validation, without the journal
/// freshness gate that `SearchIndex` snapshots legitimately require.
#[cfg(test)]
pub(crate) async fn query_rows_for_test(
    table: &Table,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchProjectionRow>, StoreError> {
    query_rows(table, None, limit, Some(query)).await
}

async fn query_rows(
    table: &Table,
    filter: Option<String>,
    limit: usize,
    fts: Option<&str>,
) -> Result<Vec<SearchProjectionRow>, StoreError> {
    if let Some(query) = fts {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let native_limit = i64::try_from(limit).map_err(|_| StoreError::InvalidInput)?;
        let mut query = table
            .query()
            .full_text_search(FullTextSearchQuery::new(query.into()).limit(Some(native_limit)))
            .select(Select::columns(&SEARCH_COLUMNS));
        // The builder adds an outer limit of ten. Clear it: flat matches are
        // not ordered, so truncation must follow selection, not precede it.
        // The independent native limit still bounds indexed top-k work.
        query.mut_query().limit = None;
        if let Some(filter) = filter {
            query = query.only_if(filter);
        }
        let mut stream = query.execute().await.map_err(|_| StoreError::LanceDb)?;
        let mut selected = Vec::with_capacity(limit);
        while let Some(batch) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
            let batch = batch.map_err(|_| StoreError::LanceDb)?;
            select_fts_batch(&batch, &mut selected, limit).await?;
        }
        let rows = selected.into_iter().map(|(_, row)| row).collect::<Vec<_>>();
        ensure_unique_row_ids(&rows)?;
        return Ok(rows);
    }
    let mut query = table
        .query()
        .select(Select::columns(&SEARCH_COLUMNS))
        .limit(limit);
    if let Some(filter) = filter {
        query = query.only_if(filter);
    }
    let batches = crate::collect_batches(&query)
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let mut rows = rows_from_batches(batches, false)?;
    rows.sort();
    Ok(rows)
}

async fn select_fts_batch(
    batch: &RecordBatch,
    selected: &mut Vec<(f32, SearchProjectionRow)>,
    limit: usize,
) -> Result<(), StoreError> {
    let ids = batch
        .column_by_name("row_id")
        .and_then(|array| array.as_any().downcast_ref::<StringArray>())
        .ok_or(StoreError::StoreCorrupt)?;
    let scores = batch
        .column_by_name("_score")
        .and_then(|array| array.as_any().downcast_ref::<Float32Array>())
        .ok_or(StoreError::StoreCorrupt)?;
    for index in 0..batch.num_rows() {
        if ids.is_null(index) || scores.is_null(index) || !scores.value(index).is_finite() {
            return Err(StoreError::StoreCorrupt);
        }
        let score = scores.value(index);
        let position = selected.partition_point(|(other_score, row)| {
            other_score
                .total_cmp(&score)
                .reverse()
                .then_with(|| row.row_id.as_str().cmp(ids.value(index)))
                .is_le()
        });
        if position < limit {
            // The existing decoder validates and owns only this contender's
            // fields. Never retain slices backed by a losing batch's buffers.
            let row = rows_from_batches(vec![batch.slice(index, 1)], false)?
                .pop()
                .ok_or(StoreError::StoreCorrupt)?;
            if selected.len() == limit {
                selected.pop();
            }
            selected.insert(position, (score, row));
        }
        if index % 256 == 255 {
            tokio::task::yield_now().await;
        }
    }
    tokio::task::yield_now().await;
    Ok(())
}

fn ensure_unique_row_ids(rows: &[SearchProjectionRow]) -> Result<(), StoreError> {
    let mut ids = rows
        .iter()
        .map(|row| row.row_id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn filter_sql(filter: &SearchHardFilter) -> Option<String> {
    let mut clauses = vec!["row_variant != 'checkpoint'".to_owned()];
    let methods = if filter.method_proposal_revisions.is_empty() {
        "FALSE".into()
    } else {
        format!(
            "candidate_id IN ({})",
            filter
                .method_proposal_revisions
                .iter()
                .map(|value| sql_literal(value))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    clauses.push(format!(
        "(object_kind IS NULL OR object_kind != 'revision_proposal_revision' OR ({methods}))"
    ));
    if let Some(revisions) = &filter.procedure_revisions {
        let allowed = if revisions.is_empty() {
            "FALSE".into()
        } else {
            format!(
                "candidate_id IN ({})",
                revisions
                    .iter()
                    .map(|value| sql_literal(value))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        clauses.push(format!(
            "(object_kind IS NULL OR object_kind != 'procedure_revision' OR ({allowed}))"
        ));
    }
    if filter.object_only {
        clauses.push("row_variant = 'object'".into());
    }
    if filter.current_only {
        clauses.push("currentness = 'current'".into());
    }
    let scope = [
        ("task_id", filter.task_id.as_ref()),
        ("repository_id", filter.repository_id.as_ref()),
        ("worktree_id", filter.worktree_id.as_ref()),
    ]
    .into_iter()
    .filter_map(|(column, value)| value.map(|value| format!("{column} = {}", sql_literal(value))))
    .collect::<Vec<_>>();
    if !scope.is_empty() {
        clauses.push(format!("({})", scope.join(" OR ")));
    }
    for (column, value) in [
        ("source_kind", filter.source_kind.as_ref()),
        ("source_role", filter.source_role.as_ref()),
        ("authority", filter.authority.as_ref()),
        ("lifecycle", filter.lifecycle.as_ref()),
    ] {
        if let Some(value) = value {
            clauses.push(format!("{column} = {}", sql_literal(value)));
        }
    }
    if !filter.suppressed_hashes.is_empty() {
        let values = filter
            .suppressed_hashes
            .iter()
            .map(|value| sql_literal(value))
            .collect::<Vec<_>>()
            .join(", ");
        clauses.push(format!(
            "(suppression_ref_hash IS NULL OR suppression_ref_hash NOT IN ({values}))"
        ));
    }
    if !filter.suppressed_refs.is_empty() {
        let values = filter
            .suppressed_refs
            .iter()
            .map(|value| sql_literal(value))
            .collect::<Vec<_>>()
            .join(", ");
        clauses.push(format!(
            "candidate_id NOT IN ({values}) AND source_ref NOT IN ({values})"
        ));
    }
    if let Some(at_us) = filter.event_time_as_of {
        clauses.push(format!(
            "time_domain = 'event_time' AND event_time_us <= {at_us}"
        ));
    }
    if let Some((start_us, end_us)) = filter.event_time_interval {
        clauses.push(format!(
            "time_domain = 'event_time' AND event_time_us >= {start_us} AND event_time_us < {end_us}"
        ));
    }
    if let Some(sequence) = filter.source_sequence_at_most {
        clauses.push(format!(
            "time_domain = 'source_sequence' AND source_sequence <= {sequence}"
        ));
    }
    Some(clauses.join(" AND "))
}

fn combine_filter(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("({left}) AND ({right})")),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SearchProjectionRow {
    pub row_id: String,
    pub row_variant: String,
    pub candidate_id: Option<String>,
    pub source_ref: Option<String>,
    pub source_kind: Option<String>,
    pub text: String,
    pub source_role: Option<String>,
    pub content_trust: Option<String>,
    pub capture_completeness: Option<String>,
    pub instruction_authority: String,
    pub object_kind: Option<String>,
    pub currentness: Option<String>,
    pub lifecycle: Option<String>,
    pub epistemic: Option<String>,
    pub authority: Option<String>,
    pub task_id: Option<String>,
    pub repository_id: Option<String>,
    pub worktree_id: Option<String>,
    pub event_time_us: i64,
    pub recorded_at_us: i64,
    pub source_sequence: u64,
    pub time_domain: String,
    pub retrieval_completeness: String,
    pub suppression_ref_hash: Option<String>,
    pub source_event_seq: u64,
    pub projection_generation: u64,
}

impl SearchProjectionRow {
    pub fn checkpoint(frontier: u64) -> Self {
        Self {
            row_id: SEARCH_CHECKPOINT_ID.into(),
            row_variant: "checkpoint".into(),
            candidate_id: None,
            source_ref: None,
            source_kind: None,
            text: String::new(),
            source_role: None,
            content_trust: None,
            capture_completeness: None,
            instruction_authority: "none".into(),
            object_kind: None,
            currentness: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            task_id: None,
            repository_id: None,
            worktree_id: None,
            event_time_us: 0,
            recorded_at_us: 0,
            source_sequence: 0,
            time_domain: "none".into(),
            retrieval_completeness: "complete".into(),
            suppression_ref_hash: None,
            source_event_seq: frontier,
            projection_generation: SEARCH_PROJECTION_GENERATION,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.row_id.is_empty()
            || self.projection_generation != SEARCH_PROJECTION_GENERATION
            || self.instruction_authority != "none"
            || self.event_time_us < 0
            || self.recorded_at_us < 0
            || !matches!(
                self.time_domain.as_str(),
                "none" | "event_time" | "source_sequence"
            )
            || !matches!(self.retrieval_completeness.as_str(), "complete" | "partial")
        {
            return Err(StoreError::StoreCorrupt);
        }
        if self.row_id == SEARCH_CHECKPOINT_ID {
            if self.candidate_id.is_some()
                || self.source_ref.is_some()
                || self.source_kind.is_some()
                || !self.text.is_empty()
                || self.source_role.is_some()
                || self.content_trust.is_some()
                || self.capture_completeness.is_some()
                || self.object_kind.is_some()
                || self.currentness.is_some()
                || self.lifecycle.is_some()
                || self.epistemic.is_some()
                || self.authority.is_some()
                || self.task_id.is_some()
                || self.repository_id.is_some()
                || self.worktree_id.is_some()
                || self.suppression_ref_hash.is_some()
                || self.row_variant != "checkpoint"
                || self.event_time_us != 0
                || self.recorded_at_us != 0
                || self.source_sequence != 0
                || self.time_domain != "none"
                || self.retrieval_completeness != "complete"
            {
                return Err(StoreError::StoreCorrupt);
            }
        } else if self.candidate_id.as_deref().is_none_or(str::is_empty)
            || self.source_ref.as_deref().is_none_or(str::is_empty)
            || self.source_kind.as_deref().is_none_or(str::is_empty)
            || self.text.is_empty()
            || self.text.len() > 16 * 1024
        {
            return Err(StoreError::StoreCorrupt);
        } else if self.row_variant == "object" {
            if self.source_kind.as_deref() != Some("object_projection")
                || self.object_kind.as_deref().is_none_or(str::is_empty)
                || !matches!(
                    self.object_kind.as_deref(),
                    Some(
                        "atom_revision"
                            | "task"
                            | "workstream"
                            | "attempt"
                            | "experiment_run"
                            | "result_evidence"
                            | "work_artifact"
                            | "scenario"
                            | "core_membership"
                            | "global_support_contract"
                            | "global_support_validation"
                            | "procedure_revision"
                            | "revision_proposal_revision"
                            | "semantic_digest"
                            | "wiki_projection"
                    )
                )
                || !matches!(self.currentness.as_deref(), Some("current" | "historical"))
                || !matches!(
                    self.lifecycle.as_deref(),
                    Some("active" | "terminal" | "unknown")
                )
                || !self.row_id.starts_with("search:object:")
                || self
                    .candidate_id
                    .as_deref()
                    .is_none_or(|value| !valid_entity_ref(value))
                || self
                    .source_ref
                    .as_deref()
                    .is_none_or(|value| !valid_entity_ref(value))
                || self.source_role.is_some()
                || self.content_trust.is_some()
                || self.capture_completeness.is_some()
                || self.suppression_ref_hash.is_some()
                || !valid_object_metadata(self)
            {
                return Err(StoreError::StoreCorrupt);
            }
        } else if self.row_variant == "evidence_surface" {
            let source_ref = self.source_ref.as_deref().unwrap_or_default();
            let candidate = self.candidate_id.as_deref().unwrap_or_default();
            let mut parts = candidate.rsplitn(3, ':');
            let span_hash = parts.next().unwrap_or_default();
            let candidate_shape = is_hex_64(span_hash)
                && parts
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .is_some_and(|value| value > 0)
                && parts.next() == Some(source_ref);
            if self.source_kind.as_deref() != Some("evidence_surface")
                || !valid_uuid(source_ref)
                || !candidate_shape
                || self.row_id != format!("search:evidence:{source_ref}:{}", span_hash)
                || !valid_source_role(self.source_role.as_deref())
                || !matches!(
                    self.content_trust.as_deref(),
                    Some(
                        "user_statement"
                            | "observed"
                            | "agent_claim"
                            | "imported_claim"
                            | "untrusted_source_content"
                    )
                )
                || !valid_capture_completeness(self.capture_completeness.as_deref())
                || self
                    .suppression_ref_hash
                    .as_deref()
                    .is_none_or(|value| !is_hex_64(value))
                || self.object_kind.is_some()
                || self.currentness.is_some()
                || self.lifecycle.is_some()
                || self.epistemic.is_some()
                || self.authority.is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        } else {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }
}

fn valid_source_role(value: Option<&str>) -> bool {
    matches!(
        value,
        Some("user" | "assistant" | "tool" | "host" | "imported")
    )
}

fn valid_capture_completeness(value: Option<&str>) -> bool {
    matches!(value, Some("complete" | "partial" | "opaque"))
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_uuid(value: &str) -> bool {
    evertrace_domain::revision::RevisionId::from_str(value).is_ok()
        || evertrace_domain::ids::AnyPublicId::from_str(value).is_ok()
}

fn valid_entity_ref(value: &str) -> bool {
    valid_uuid(value)
}

fn valid_object_metadata(row: &SearchProjectionRow) -> bool {
    matches!(
        row.epistemic.as_deref(),
        Some(
            "observed"
                | "current"
                | "evidence"
                | "not_applicable"
                | "unverified"
                | "supported"
                | "derived"
                | "disputed"
                | "refuted"
        ) | None
    ) && matches!(
        row.authority.as_deref(),
        Some(
            "none"
                | "user_explicit"
                | "objective_evidence"
                | "agent_inferred"
                | "imported_claim"
                | "project_policy"
        ) | None
    ) && match row.time_domain.as_str() {
        "none" => row.event_time_us == 0 && row.source_sequence == 0,
        "event_time" => row.event_time_us > 0 && row.source_sequence == 0,
        "source_sequence" => row.source_sequence > 0 && row.event_time_us == 0,
        _ => false,
    }
}

pub fn search_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("row_id", DataType::Utf8, false),
        Field::new("row_variant", DataType::Utf8, false),
        Field::new("candidate_id", DataType::Utf8, true),
        Field::new("source_ref", DataType::Utf8, true),
        Field::new("source_kind", DataType::Utf8, true),
        Field::new("text", DataType::Utf8, false),
        Field::new("source_role", DataType::Utf8, true),
        Field::new("content_trust", DataType::Utf8, true),
        Field::new("capture_completeness", DataType::Utf8, true),
        Field::new("instruction_authority", DataType::Utf8, false),
        Field::new("object_kind", DataType::Utf8, true),
        Field::new("currentness", DataType::Utf8, true),
        Field::new("lifecycle", DataType::Utf8, true),
        Field::new("epistemic", DataType::Utf8, true),
        Field::new("authority", DataType::Utf8, true),
        Field::new("task_id", DataType::Utf8, true),
        Field::new("repository_id", DataType::Utf8, true),
        Field::new("worktree_id", DataType::Utf8, true),
        Field::new("event_time_us", DataType::Int64, false),
        Field::new("recorded_at_us", DataType::Int64, false),
        Field::new("source_sequence", DataType::UInt64, false),
        Field::new("time_domain", DataType::Utf8, false),
        Field::new("retrieval_completeness", DataType::Utf8, false),
        Field::new("suppression_ref_hash", DataType::Utf8, true),
        Field::new("source_event_seq", DataType::UInt64, false),
        Field::new("projection_generation", DataType::UInt64, false),
    ]))
}

pub(crate) fn search_batch(rows: &[SearchProjectionRow]) -> Result<RecordBatch, StoreError> {
    for row in rows {
        row.validate()?;
    }
    let optional = |values: Vec<Option<&str>>| Arc::new(StringArray::from(values)) as ArrayRef;
    RecordBatch::try_new(
        search_schema(),
        vec![
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.row_id.as_str()),
            )),
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.row_variant.as_str()),
            )),
            optional(rows.iter().map(|row| row.candidate_id.as_deref()).collect()),
            optional(rows.iter().map(|row| row.source_ref.as_deref()).collect()),
            optional(rows.iter().map(|row| row.source_kind.as_deref()).collect()),
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.text.as_str()),
            )),
            optional(rows.iter().map(|row| row.source_role.as_deref()).collect()),
            optional(
                rows.iter()
                    .map(|row| row.content_trust.as_deref())
                    .collect(),
            ),
            optional(
                rows.iter()
                    .map(|row| row.capture_completeness.as_deref())
                    .collect(),
            ),
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.instruction_authority.as_str()),
            )),
            optional(rows.iter().map(|row| row.object_kind.as_deref()).collect()),
            optional(rows.iter().map(|row| row.currentness.as_deref()).collect()),
            optional(rows.iter().map(|row| row.lifecycle.as_deref()).collect()),
            optional(rows.iter().map(|row| row.epistemic.as_deref()).collect()),
            optional(rows.iter().map(|row| row.authority.as_deref()).collect()),
            optional(rows.iter().map(|row| row.task_id.as_deref()).collect()),
            optional(
                rows.iter()
                    .map(|row| row.repository_id.as_deref())
                    .collect(),
            ),
            optional(rows.iter().map(|row| row.worktree_id.as_deref()).collect()),
            Arc::new(Int64Array::from_iter_values(
                rows.iter().map(|row| row.event_time_us),
            )),
            Arc::new(Int64Array::from_iter_values(
                rows.iter().map(|row| row.recorded_at_us),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.source_sequence),
            )),
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.time_domain.as_str()),
            )),
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.retrieval_completeness.as_str()),
            )),
            optional(
                rows.iter()
                    .map(|row| row.suppression_ref_hash.as_deref())
                    .collect(),
            ),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.source_event_seq),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.projection_generation),
            )),
        ],
    )
    .map_err(|_| StoreError::StoreCorrupt)
}

/// Physical row addresses read in the same pass as the complete search rows.
///
/// The map is a private per-call companion bound to the exact dataset version it
/// was read from; it is never persisted, cached or reused as a logical identity.
/// The checkpoint row is included, so a complete map covers every old row.
pub(crate) struct SearchRowAddresses {
    table: Table,
    dataset: Arc<lance::Dataset>,
    by_row_id: std::collections::BTreeMap<String, u64>,
}

impl SearchRowAddresses {
    pub(crate) fn version(&self) -> u64 {
        self.dataset.version().version
    }

    pub(crate) fn dataset_for(&self, table: &Table) -> Option<Arc<lance::Dataset>> {
        match (self.table.dataset(), table.dataset()) {
            (Some(owner), Some(current)) if std::ptr::eq(owner, current) => {
                Some(Arc::clone(&self.dataset))
            }
            _ => None,
        }
    }

    pub(crate) fn get(&self, row_id: &str) -> Option<u64> {
        self.by_row_id.get(row_id).copied()
    }
}

/// Read every persisted search row together with its physical `_rowaddr` from
/// one dataset version. The 26-column decoder is unchanged: only the extra
/// system column is stripped before it runs.
pub(crate) async fn read_search_rows_with_addresses(
    table: &Table,
) -> Result<(Vec<SearchProjectionRow>, SearchRowAddresses), StoreError> {
    table
        .checkout_latest()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != search_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let dataset = table
        .dataset()
        .ok_or(StoreError::StoreCorrupt)?
        .get()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let version = dataset.version().version;
    let mut columns = SEARCH_COLUMNS.to_vec();
    columns.push(ROW_ADDR);
    let batches = crate::collect_batches(&table.query().select(Select::columns(&columns)))
        .await
        .map_err(|_| StoreError::LanceDb)?;
    if table.version().await.map_err(|_| StoreError::LanceDb)? != version {
        return Err(StoreError::StoreCorrupt);
    }
    let projected = (0..SEARCH_COLUMNS.len()).collect::<Vec<_>>();
    let mut rows_batches = Vec::with_capacity(batches.len());
    let mut by_row_id = std::collections::BTreeMap::new();
    let mut seen_addresses = std::collections::BTreeSet::new();
    for batch in batches {
        let names = batch.schema();
        let names = names.fields();
        if names.len() != SEARCH_COLUMNS.len() + 1
            || names[..SEARCH_COLUMNS.len()]
                .iter()
                .map(|field| field.name().as_str())
                .ne(SEARCH_COLUMNS)
            || names[SEARCH_COLUMNS.len()].name() != ROW_ADDR
        {
            return Err(StoreError::StoreCorrupt);
        }
        let ids = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or(StoreError::StoreCorrupt)?;
        let addresses = batch
            .column(SEARCH_COLUMNS.len())
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        if addresses.null_count() != 0
            || ids.len() != batch.num_rows()
            || addresses.len() != batch.num_rows()
        {
            return Err(StoreError::StoreCorrupt);
        }
        for index in 0..batch.num_rows() {
            let address = addresses.value(index);
            if by_row_id
                .insert(ids.value(index).to_owned(), address)
                .is_some()
                || !seen_addresses.insert(address)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        rows_batches.push(
            batch
                .project(&projected)
                .map_err(|_| StoreError::StoreCorrupt)?,
        );
    }
    let rows = rows_from_batches(rows_batches, true)?;
    if by_row_id.len() != rows.len() || rows.iter().any(|row| !by_row_id.contains_key(&row.row_id))
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok((
        rows,
        SearchRowAddresses {
            table: table.clone(),
            dataset,
            by_row_id,
        },
    ))
}

pub async fn read_search_rows(table: &Table) -> Result<Vec<SearchProjectionRow>, StoreError> {
    table
        .checkout_latest()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    read_search_rows_at_current_version(table).await
}

/// Decode the complete search family from whatever version `table` is pinned
/// to. Ordinary callers keep `read_search_rows`' latest-version contract.
pub(crate) async fn read_search_rows_at_current_version(
    table: &Table,
) -> Result<Vec<SearchProjectionRow>, StoreError> {
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != search_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let batches = crate::collect_batches(&table.query())
        .await
        .map_err(|_| StoreError::LanceDb)?;
    rows_from_batches(batches, true)
}

pub(crate) async fn read_search_checkpoint(table: &Table) -> Result<u64, StoreError> {
    table
        .checkout_latest()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != search_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let rows = query_rows(
        table,
        Some(format!("row_id = '{SEARCH_CHECKPOINT_ID}'")),
        2,
        None,
    )
    .await?;
    let [checkpoint] = rows.as_slice() else {
        return Err(StoreError::StoreCorrupt);
    };
    if checkpoint.row_id != SEARCH_CHECKPOINT_ID {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(checkpoint.source_event_seq)
}

fn rows_from_batches(
    batches: Vec<RecordBatch>,
    require_checkpoint: bool,
) -> Result<Vec<SearchProjectionRow>, StoreError> {
    let mut rows = Vec::new();
    for batch in batches {
        let string = |index| {
            batch
                .column(index)
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or(StoreError::StoreCorrupt)
        };
        let ids = string(0)?;
        let variants = string(1)?;
        let candidates = string(2)?;
        let refs = string(3)?;
        let kinds = string(4)?;
        let texts = string(5)?;
        let roles = string(6)?;
        let trust = string(7)?;
        let capture = string(8)?;
        let instruction = string(9)?;
        let object_kinds = string(10)?;
        let currentness = string(11)?;
        let lifecycles = string(12)?;
        let epistemics = string(13)?;
        let authorities = string(14)?;
        let tasks = string(15)?;
        let repositories = string(16)?;
        let worktrees = string(17)?;
        let events = batch
            .column(18)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        let recorded = batch
            .column(19)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        let sequences = batch
            .column(20)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        let time_domains = string(21)?;
        let retrieval_completeness = string(22)?;
        let suppression = string(23)?;
        let frontiers = batch
            .column(24)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        let generations = batch
            .column(25)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        let value =
            |array: &StringArray, index| (!array.is_null(index)).then(|| array.value(index).into());
        for index in 0..batch.num_rows() {
            let row = SearchProjectionRow {
                row_id: ids.value(index).into(),
                row_variant: variants.value(index).into(),
                candidate_id: value(candidates, index),
                source_ref: value(refs, index),
                source_kind: value(kinds, index),
                text: texts.value(index).into(),
                source_role: value(roles, index),
                content_trust: value(trust, index),
                capture_completeness: value(capture, index),
                instruction_authority: instruction.value(index).into(),
                object_kind: value(object_kinds, index),
                currentness: value(currentness, index),
                lifecycle: value(lifecycles, index),
                epistemic: value(epistemics, index),
                authority: value(authorities, index),
                task_id: value(tasks, index),
                repository_id: value(repositories, index),
                worktree_id: value(worktrees, index),
                event_time_us: events.value(index),
                recorded_at_us: recorded.value(index),
                source_sequence: sequences.value(index),
                time_domain: time_domains.value(index).into(),
                retrieval_completeness: retrieval_completeness.value(index).into(),
                suppression_ref_hash: value(suppression, index),
                source_event_seq: frontiers.value(index),
                projection_generation: generations.value(index),
            };
            row.validate()?;
            rows.push(row);
        }
    }
    if require_checkpoint {
        rows.sort();
        if rows
            .iter()
            .filter(|row| row.row_id == SEARCH_CHECKPOINT_ID)
            .count()
            != 1
            || rows.windows(2).any(|pair| pair[0].row_id == pair[1].row_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
    } else {
        ensure_unique_row_ids(&rows)?;
    }
    Ok(rows)
}

pub fn build_evidence_surface(
    receipt: &SourceReceipt,
    observation: &SourceObservation,
    protected_payload: &[u8],
    surface_eligible: bool,
) -> Result<Option<EvidenceSurface>, EvidenceError> {
    receipt.validate()?;
    observation.validate()?;
    if receipt.source_observation_id != observation.source_observation_id
        || receipt.source_receipt_id != observation.source_receipt_ref
        || receipt.source_instance_id != observation.source_instance_id
        || receipt.source_revision != observation.source_revision
        || receipt.source_record_identity != observation.source_record_identity
        || receipt.observation_role != observation.observation_role
        || receipt.capture_completeness != observation.capture_completeness
    {
        return Err(EvidenceError::Invalid);
    }
    if !surface_eligible
        || receipt.unsupported_record_classification.is_some()
        || receipt.archive_mode == SourceArchiveMode::Redacted
    {
        return Ok(None);
    }
    let text = match std::str::from_utf8(protected_payload) {
        Ok(value) => canonicalize_text(value),
        Err(_) => return Ok(None),
    };
    if text.is_empty()
        || text.len() > evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES
        || text.bytes().any(|byte| byte == 0)
    {
        return Ok(None);
    }
    let span_hash = evidence_span_hash(
        observation.source_observation_id,
        observation.canonicalization_revision,
        &text,
    )?;
    let surface = EvidenceSurface {
        source_observation_revision_ref: observation.source_observation_id,
        source_role: observation.source_role,
        content_trust: observation.content_trust,
        instruction_authority: InstructionAuthority::None,
        task_id: receipt.task_id,
        repository_instance_id: receipt.repository_instance_id,
        worktree_instance_id: receipt.worktree_instance_id,
        event_time_us: receipt.event_time_us,
        recorded_at_us: receipt.recorded_at_us,
        source_sequence: receipt.source_sequence,
        capture_completeness: observation.capture_completeness,
        canonicalization_version: observation.canonicalization_revision,
        span_hash: hex(&span_hash),
        projection_generation: SEARCH_PROJECTION_GENERATION,
        protected_text: text,
    };
    surface.validate()?;
    Ok(Some(surface))
}

pub fn unsupported_surface_reason(classification: UnsupportedRecordClassification) -> &'static str {
    match classification {
        UnsupportedRecordClassification::UnknownRecordType => "unsupported_record_type",
        UnsupportedRecordClassification::Reasoning => "reasoning_not_searchable",
        UnsupportedRecordClassification::Binary => "binary_not_searchable",
        UnsupportedRecordClassification::UnboundedToolOutput => "unbounded_tool_output",
    }
}

fn canonicalize_text(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::ids::CommandId;
    use lancedb::index::{Index, scalar::FtsIndexBuilder};

    use super::*;
    use crate::{DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload};

    fn object_row() -> SearchProjectionRow {
        SearchProjectionRow {
            row_id: "search:object:test".into(),
            row_variant: "object".into(),
            candidate_id: Some("01890f47-6a4a-7cc1-98b9-01890f476c00".into()),
            source_ref: Some("01890f47-6a4a-7cc1-98b9-01890f476c01".into()),
            source_kind: Some("object_projection".into()),
            text: "bounded".into(),
            source_role: None,
            content_trust: None,
            capture_completeness: None,
            instruction_authority: "none".into(),
            object_kind: Some("atom_revision".into()),
            currentness: Some("current".into()),
            lifecycle: Some("active".into()),
            epistemic: Some("unverified".into()),
            authority: Some("agent_inferred".into()),
            task_id: None,
            repository_id: None,
            worktree_id: None,
            event_time_us: 1,
            recorded_at_us: 0,
            source_sequence: 0,
            time_domain: "event_time".into(),
            retrieval_completeness: "complete".into(),
            suppression_ref_hash: None,
            source_event_seq: 1,
            projection_generation: SEARCH_PROJECTION_GENERATION,
        }
    }

    #[test]
    fn object_rows_reject_open_identifiers_metadata_and_time_shapes() {
        assert!(object_row().validate().is_ok());
        let mut invalid = object_row();
        invalid.source_ref = Some("printable-but-untyped".into());
        assert_eq!(invalid.validate(), Err(StoreError::StoreCorrupt));
        let mut invalid = object_row();
        invalid.object_kind = Some("future_kind".into());
        assert_eq!(invalid.validate(), Err(StoreError::StoreCorrupt));
        let mut invalid = object_row();
        invalid.authority = Some("self_authorized".into());
        assert_eq!(invalid.validate(), Err(StoreError::StoreCorrupt));
        let mut invalid = object_row();
        invalid.source_sequence = 1;
        assert_eq!(invalid.validate(), Err(StoreError::StoreCorrupt));
    }

    #[test]
    fn snapshot_checkpoint_requires_exactly_one_row() {
        let checkpoint = SearchProjectionRow::checkpoint(7);
        assert_eq!(
            exact_checkpoint_frontier(std::slice::from_ref(&checkpoint)),
            Ok(7)
        );
        assert_eq!(
            exact_checkpoint_frontier(&[checkpoint.clone(), checkpoint]),
            Err(StoreError::StoreCorrupt)
        );
        let row = object_row();
        let mut other = row.clone();
        other.row_id.push_str(":other");
        assert_eq!(
            rows_from_batches(
                vec![search_batch(&[row.clone(), other, row]).unwrap()],
                false
            ),
            Err(StoreError::StoreCorrupt),
            "rank-preserving queries must still reject nonadjacent duplicate IDs"
        );
    }

    #[tokio::test]
    async fn real_fts_rank_order_survives_bounded_wrapper() {
        const QUERY: &str = "needle";
        const STRONG_ID: &str = "01890f47-6a4a-7cc1-98b9-01890f476c11";
        let weak_ids = (0x00..=0x0a)
            .map(|suffix| format!("01890f47-6a4a-7cc1-98b9-01890f476c{suffix:02x}"))
            .collect::<Vec<_>>();
        assert!(weak_ids.iter().all(|weak| weak.as_str() < STRONG_ID));

        let weak_text = format!("needle {}", "background ".repeat(24));
        let mut rows = Vec::with_capacity(12);
        for candidate_id in &weak_ids {
            let mut row = object_row();
            row.row_id = format!("search:object:{candidate_id}");
            row.candidate_id = Some(candidate_id.clone());
            row.text = weak_text.clone();
            rows.push(row);
        }
        let mut strong = object_row();
        strong.row_id = format!("search:object:{STRONG_ID}");
        strong.candidate_id = Some(STRONG_ID.into());
        strong.text = "needle ".repeat(18);
        rows.push(strong);

        let temp = tempfile::tempdir().unwrap();
        let database = lancedb::connect(temp.path().to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let table = database
            .create_table(SEARCH_TABLE, search_batch(&rows).unwrap())
            .execute()
            .await
            .unwrap();
        table
            .create_index(
                &["text"],
                Index::FTS(
                    FtsIndexBuilder::default()
                        .base_tokenizer("icu".into())
                        .stem(false)
                        .remove_stop_words(false)
                        .ascii_folding(true)
                        .with_position(false),
                ),
            )
            .execute()
            .await
            .unwrap();

        let indices = table.list_indices().await.unwrap();
        eprintln!("r529_fts_index_count={}", indices.len());
        for index in &indices {
            eprintln!("r529_fts_index_columns={:?}", index.columns);
        }
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0].columns, vec!["text".to_owned()]);

        let filter = SearchHardFilter {
            lifecycle: Some("active".into()),
            object_only: true,
            current_only: true,
            ..SearchHardFilter::default()
        };
        let filter = filter_sql(&filter).unwrap();
        let native_query = table
            .query()
            .full_text_search(FullTextSearchQuery::new(QUERY.into()))
            .select(Select::columns(&SEARCH_COLUMNS))
            .limit(3)
            .only_if(filter.clone());
        let native_batches = crate::collect_batches(&native_query).await.unwrap();
        let mut native_ids = Vec::new();
        let mut native_scores = Vec::new();
        for batch in native_batches {
            let candidate_index = batch.schema().index_of("candidate_id").unwrap();
            let candidates = batch
                .column(candidate_index)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let scores = batch
                .column_by_name("_score")
                .unwrap()
                .as_any()
                .downcast_ref::<arrow_array::Float32Array>()
                .unwrap();
            native_scores.extend(scores.values().iter().copied());
            for row in 0..batch.num_rows() {
                assert!(!candidates.is_null(row));
                native_ids.push(candidates.value(row).to_owned());
            }
        }

        let wrapper_ids = query_rows(&table, Some(filter.clone()), 3, Some(QUERY))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.candidate_id.unwrap())
            .collect::<Vec<_>>();
        eprintln!("r529_native_top_three_candidate_ids={native_ids:?}");
        eprintln!("r529_native_scores={native_scores:?}");
        eprintln!("r529_query_rows_top_three_candidate_ids={wrapper_ids:?}");
        assert_eq!(native_ids.len(), 3, "native FTS must return top three");
        assert_eq!(native_scores.len(), 3);
        assert!(native_scores[0] > native_scores[1] && native_scores[0] > native_scores[2]);
        assert_eq!(
            native_ids[0], STRONG_ID,
            "fixture precondition: designated strong row must lead native FTS; IDs={native_ids:?}, scores={native_scores:?}"
        );
        // Equal-score weak rows may tie differently between two native queries.
        assert_eq!(wrapper_ids.len(), native_ids.len());
        assert_eq!(
            wrapper_ids[0], native_ids[0],
            "query_rows must preserve the strictly strongest native FTS hit"
        );

        // Updating text invalidates the index's covered text. Normal searches
        // must rank these flat-evaluated matches before applying their limit too.
        table
            .update()
            .column("text", "concat(text, ' ')")
            .execute()
            .await
            .unwrap();
        let ordered_query = table
            .query()
            .full_text_search(FullTextSearchQuery::new(QUERY.into()))
            .select(Select::columns(&SEARCH_COLUMNS))
            .only_if(filter.clone())
            .limit(rows.len());
        let mut scored = Vec::new();
        for batch in crate::collect_batches(&ordered_query).await.unwrap() {
            let ids = batch
                .column_by_name("candidate_id")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let scores = batch
                .column_by_name("_score")
                .unwrap()
                .as_any()
                .downcast_ref::<arrow_array::Float32Array>()
                .unwrap();
            for index in 0..batch.num_rows() {
                scored.push((scores.value(index), ids.value(index).to_owned()));
            }
        }
        let strong_emission_index = scored.iter().position(|(_, id)| id == STRONG_ID);
        assert!(
            strong_emission_index.is_some_and(|index| index >= 10),
            "fixture precondition: the strong row must be physically emitted at raw index >= 10; index={strong_emission_index:?}, emitted={scored:?}"
        );
        scored.sort_by(|left, right| right.0.total_cmp(&left.0));
        assert_eq!(scored.len(), rows.len());
        assert_eq!(scored[0].1, STRONG_ID);
        assert!(scored[0].0 > scored[1].0);
        let updated = query_rows(&table, Some(filter), 3, Some(QUERY))
            .await
            .unwrap();
        assert_eq!(
            updated[0].candidate_id.as_deref(),
            Some(scored[0].1.as_str()),
            "flat-evaluated text updates must retain the strongest result before the limit"
        );
    }

    #[tokio::test]
    async fn fts_selector_caps_orders_and_rejects_invalid_selected_rows() {
        let with_scores = |batch: RecordBatch, scores: Vec<f32>| {
            assert_eq!(batch.num_rows(), scores.len());
            let mut fields = batch.schema().fields().iter().cloned().collect::<Vec<_>>();
            fields.push(Arc::new(Field::new("_score", DataType::Float32, false)));
            let mut columns = batch.columns().to_vec();
            columns.push(Arc::new(Float32Array::from(scores)) as ArrayRef);
            RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).unwrap()
        };
        let id = |suffix: &str| format!("search:object:01890f47-6a4a-7cc1-98b9-01890f476{suffix}");
        let row = |suffix: &str| {
            let mut row = object_row();
            row.row_id = id(suffix);
            row.candidate_id = Some(row.row_id.trim_start_matches("search:object:").into());
            row
        };
        let selected_ids = |selected: &[(f32, SearchProjectionRow)]| {
            selected
                .iter()
                .map(|(_, row)| row.row_id.clone())
                .collect::<Vec<_>>()
        };
        let mut selected = Vec::new();
        let first = with_scores(
            search_batch(&[row("c23"), row("c22")]).unwrap(),
            vec![0.5, 0.5],
        );
        select_fts_batch(&first, &mut selected, 2).await.unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected_ids(&selected), vec![id("c22"), id("c23")]);
        let late = with_scores(
            search_batch(&[row("c24"), row("c21")]).unwrap(),
            vec![0.9, 0.5],
        );
        select_fts_batch(&late, &mut selected, 2).await.unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected_ids(&selected), vec![id("c24"), id("c21")]);
        let mut duplicates = Vec::new();
        let duplicate = with_scores(search_batch(&[row("c30")]).unwrap(), vec![0.9]);
        let separated = with_scores(
            search_batch(&[row("c31"), row("c30")]).unwrap(),
            vec![0.8, 0.7],
        );
        select_fts_batch(&duplicate, &mut duplicates, 3)
            .await
            .unwrap();
        select_fts_batch(&separated, &mut duplicates, 3)
            .await
            .unwrap();
        assert_eq!(
            duplicates
                .iter()
                .filter(|(_, row)| row.row_id.ends_with("c30"))
                .count(),
            2
        );
        let retained: Vec<_> = duplicates.iter().map(|p| p.1.clone()).collect();
        assert_eq!(
            ensure_unique_row_ids(&retained),
            Err(StoreError::StoreCorrupt)
        );
        let valid = search_batch(&[row("c32")]).unwrap();
        let mut columns = valid.columns().to_vec();
        columns[5] = Arc::new(StringArray::from(vec![""]));
        let malformed = with_scores(
            RecordBatch::try_new(valid.schema(), columns).unwrap(),
            vec![0.7],
        );
        assert_eq!(
            select_fts_batch(&malformed, &mut Vec::new(), 1).await,
            Err(StoreError::StoreCorrupt)
        );
        let invalid_score = with_scores(search_batch(&[row("c33")]).unwrap(), vec![f32::NAN]);
        assert_eq!(
            select_fts_batch(&invalid_score, &mut Vec::new(), 1).await,
            Err(StoreError::StoreCorrupt)
        );
    }
    #[tokio::test]
    async fn validated_frontier_snapshot_keeps_post_pin_authority_and_falls_back() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut writer = crate::JournalWriter::open(&data).await.unwrap();
        let projection = writer.project().await.unwrap();
        let index = SearchIndex::open(&data).await.unwrap();

        let shortcut = index
            .snapshot_after_validated_frontier(projection.frontier)
            .await
            .unwrap();
        assert_eq!(shortcut.frontier(), projection.frontier);
        assert_eq!(shortcut.authoritative_frontier(), projection.frontier);

        let fallback = index
            .snapshot_after_validated_frontier(projection.frontier.saturating_add(1))
            .await
            .unwrap();
        assert_eq!(fallback.frontier(), projection.frontier);
        assert_eq!(fallback.authoritative_frontier(), projection.frontier);

        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a7a").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "objects-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "search-frontier-test".into(),
                    algorithm_revision: "objects-v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        let appended = writer.commit(&command, 1).await.unwrap();
        assert!(appended.last_seq > projection.frontier);

        let stale = index
            .snapshot_after_validated_frontier(projection.frontier)
            .await
            .unwrap();
        assert_eq!(stale.authoritative_frontier(), appended.last_seq);
        assert_eq!(stale.frontier(), projection.frontier);

        let refreshed_projection = writer.project().await.unwrap();
        let refreshed = index
            .snapshot_after_validated_frontier(refreshed_projection.frontier)
            .await
            .unwrap();
        assert_eq!(refreshed.frontier(), appended.last_seq);
        assert_eq!(refreshed.authoritative_frontier(), appended.last_seq);
    }
    #[tokio::test]
    async fn two_live_snapshots_bound_the_read_permits_and_queued_maintenance_completes() {
        use std::time::Duration;
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut writer = crate::JournalWriter::open(&data).await.unwrap();
        let index = SearchIndex::open_with_read_handle(&data, writer.read_handle())
            .await
            .unwrap();
        let first = index.snapshot().await.unwrap();
        let second = index.snapshot().await.unwrap();
        // Snapshots hold a read fence, not a SQL connection: further live
        // snapshots stay usable instead of queueing behind the short permits.
        let third = index.snapshot().await.unwrap();
        assert_eq!(third.frontier(), second.frontier());
        // Queued maintenance waits for the live read fences but must not
        // deadlock behind them: releasing every snapshot completes the quiesce.
        let mut quiesce = Box::pin(writer.quiesce_for_backup());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut quiesce)
                .await
                .is_err()
        );
        drop(first);
        drop(second);
        drop(third);
        let guard = tokio::time::timeout(Duration::from_secs(5), &mut quiesce)
            .await
            .expect("queued maintenance must not deadlock behind released readers")
            .unwrap()
            .expect("no external reader holds the WAL");
        drop(quiesce);
        drop(writer.close_for_backup(guard).unwrap());
    }

    #[tokio::test]
    async fn cancelled_lease_read_keeps_the_fence_until_the_real_task_exits() {
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();
        let writer = crate::JournalWriter::open(&temp.path().join("data"))
            .await
            .unwrap();
        let readers = writer.read_handle();
        let lease = readers.search_lease().await.unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let task_readers = readers.clone();
        let task = tokio::spawn(async move {
            task_readers
                .lease_read(&lease, move |_, cancel| {
                    let _ = started.send(());
                    released
                        .recv_timeout(Duration::from_secs(3))
                        .map_err(|_| StoreError::Io)?;
                    cancel.check()
                })
                .await
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        // The outer future and its lease are gone, but the started blocking
        // closure is still alive. Maintenance must not pass it.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), readers.quiesce())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        let guard = tokio::time::timeout(Duration::from_secs(3), readers.quiesce())
            .await
            .expect("the actual task must release the fence");
        drop(guard);
        assert!(!readers.journal_rows().await.unwrap().is_empty());
        writer.sync_frontier().await.unwrap();
    }
}
