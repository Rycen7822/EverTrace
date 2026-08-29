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

use arrow_array::{Array, ArrayRef, Int64Array, RecordBatch, StringArray, UInt64Array};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use lancedb::{
    Table,
    index::scalar::FullTextSearchQuery,
    query::{QueryBase, Select},
};

use crate::{
    StoreError,
    journal::{JOURNAL_TABLE, read_journal_frontier},
};

pub const SEARCH_TABLE: &str = "evertrace_search";
pub const SEARCH_CHECKPOINT_ID: &str = "checkpoint:evertrace_search";

#[derive(Clone)]
pub struct SearchIndex {
    data_dir: PathBuf,
}

pub struct SearchSnapshot {
    table: Table,
    frontier: u64,
    authoritative_frontier: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SearchHardFilter {
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
    pub async fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let connection = lancedb::connect(data_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let table = connection
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
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
        })
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
        for attempt in 0..2 {
            let before = self.authoritative_frontier().await?;
            let snapshot = self.pinned_snapshot().await?;
            let after = self.authoritative_frontier().await?;
            if before == after || attempt == 1 {
                if snapshot.frontier > after {
                    return Err(StoreError::StoreCorrupt);
                }
                return Ok(SearchSnapshot {
                    authoritative_frontier: after,
                    ..snapshot
                });
            }
        }
        unreachable!("bounded snapshot loop always returns")
    }

    async fn pinned_snapshot(&self) -> Result<SearchSnapshot, StoreError> {
        let connection = lancedb::connect(self.data_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let table = connection
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
        Ok(SearchSnapshot {
            table,
            frontier,
            authoritative_frontier: 0,
        })
    }

    async fn authoritative_frontier(&self) -> Result<u64, StoreError> {
        let connection = lancedb::connect(self.data_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let table = connection
            .open_table(JOURNAL_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        table
            .checkout_latest()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        read_journal_frontier(&table).await
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
}

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

async fn query_rows(
    table: &Table,
    filter: Option<String>,
    limit: usize,
    fts: Option<&str>,
) -> Result<Vec<SearchProjectionRow>, StoreError> {
    let batches = if let Some(query) = fts {
        let mut query = table
            .query()
            .full_text_search(FullTextSearchQuery::new(query.into()))
            .select(Select::columns(&SEARCH_COLUMNS))
            .limit(limit);
        if let Some(filter) = filter {
            query = query.only_if(filter);
        }
        crate::collect_batches(&query)
            .await
            .map_err(|_| StoreError::LanceDb)?
    } else {
        let mut query = table
            .query()
            .select(Select::columns(&SEARCH_COLUMNS))
            .limit(limit);
        if let Some(filter) = filter {
            query = query.only_if(filter);
        }
        crate::collect_batches(&query)
            .await
            .map_err(|_| StoreError::LanceDb)?
    };
    rows_from_batches(batches, false)
}

fn filter_sql(filter: &SearchHardFilter) -> Option<String> {
    let mut clauses = vec!["row_variant != 'checkpoint'".to_owned()];
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
            projection_generation: 1,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.row_id.is_empty()
            || self.projection_generation != 1
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

pub async fn read_search_rows(table: &Table) -> Result<Vec<SearchProjectionRow>, StoreError> {
    table
        .checkout_latest()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != search_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let batches = crate::collect_batches(&table.query())
        .await
        .map_err(|_| StoreError::LanceDb)?;
    rows_from_batches(batches, true)
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
    rows.sort();
    if (require_checkpoint
        && rows
            .iter()
            .filter(|row| row.row_id == SEARCH_CHECKPOINT_ID)
            .count()
            != 1)
        || rows.windows(2).any(|pair| pair[0].row_id == pair[1].row_id)
    {
        return Err(StoreError::StoreCorrupt);
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
        projection_generation: 1,
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
    use super::*;

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
            projection_generation: 1,
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
    }
}
