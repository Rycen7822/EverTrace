//! Read-only decoder for the retired four-Lance physical layout.
//!
//! The offline converter and the offline restore of a legacy backup are the
//! only consumers. Normal opens never reach this module: the current format is
//! one SQLite database plus the Lance search projection. Nothing here writes,
//! repairs or renumbers logical history.

use std::collections::BTreeSet;
use std::path::Path;

use arrow_array::{Array, LargeStringArray, RecordBatch, StringArray, UInt64Array};
use lancedb::Table;

use crate::command::{ObjectFamily, StoreError};
use crate::journal::JournalRow;
use crate::objects::{ObjectRow, ObjectRowClass, ObjectRowKind};
use crate::relations::RelationProjectionRow;
use crate::search::SearchProjectionRow;

const LEGACY_TABLES: [&str; 4] = [
    crate::JOURNAL_TABLE,
    crate::OBJECTS_TABLE,
    crate::RELATIONS_TABLE,
    crate::SEARCH_TABLE,
];

/// One fully decoded and validated retired layout, bound to the exact bytes
/// read from `dir`. Physical versions and checkpoints are preserved; the
/// caller decides what to write where.
pub(crate) struct LegacyStore {
    pub(crate) profile: &'static str,
    pub(crate) rows: Vec<JournalRow>,
    pub(crate) journal_version: u64,
    pub(crate) object_version: u64,
    pub(crate) relation_version: Option<u64>,
    pub(crate) search_version: Option<u64>,
    pub(crate) object_checkpoint: u64,
    pub(crate) relation_checkpoint: Option<u64>,
    pub(crate) search_checkpoint: Option<u64>,
}

impl LegacyStore {
    /// The journal frontier, i.e. the last logical command row.
    pub(crate) fn frontier(&self) -> u64 {
        self.rows.last().map(|row| row.seq).unwrap_or(0)
    }

    /// The old physical table states exactly as recorded by manifest version 2.
    /// `projection_generation` is deliberately absent: that field did not exist
    /// in the retired wire shape and must not be invented.
    pub(crate) fn table_states(&self) -> crate::BackupTableStates {
        crate::BackupTableStates {
            journal: crate::BackupTableState {
                version: Some(self.journal_version),
                checkpoint: self.frontier(),
                projection_generation: None,
            },
            objects: crate::BackupTableState {
                version: Some(self.object_version),
                checkpoint: self.object_checkpoint,
                projection_generation: None,
            },
            relations: self
                .relation_version
                .map(|version| crate::BackupTableState {
                    version: Some(version),
                    checkpoint: self.relation_checkpoint.unwrap_or(0),
                    projection_generation: None,
                }),
            search: self.search_version.map(|version| crate::BackupTableState {
                version: Some(version),
                checkpoint: self.search_checkpoint.unwrap_or(0),
                projection_generation: None,
            }),
        }
    }

    /// Full history replay. The journal is the only authority; an old current
    /// table is never treated as the current fact.
    pub(crate) fn full_snapshot(&self) -> Result<crate::ProjectionSnapshot, StoreError> {
        crate::projections::reduce_journal(&self.rows)
    }
}

/// Detect the retired layout in `dir` (a canonical old `store/` directory, a
/// flat old data root or a copied backup `store/`). `None` means no old table
/// at all; a partial or mixed set is corruption, never "absent".
pub(crate) fn legacy_profile(dir: &Path) -> Result<Option<&'static str>, StoreError> {
    let mut present = BTreeSet::new();
    for name in LEGACY_TABLES {
        match std::fs::symlink_metadata(dir.join(format!("{name}.lance"))) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(StoreError::StoreCorrupt);
                }
                present.insert(name);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
    }
    let (journal, objects, relations, search) = (
        present.contains(crate::JOURNAL_TABLE),
        present.contains(crate::OBJECTS_TABLE),
        present.contains(crate::RELATIONS_TABLE),
        present.contains(crate::SEARCH_TABLE),
    );
    match (journal, objects, relations, search) {
        (false, false, false, false) => Ok(None),
        (true, true, false, false) => Ok(Some("L0001")),
        (true, true, true, true) => Ok(Some("L0002")),
        _ => Err(StoreError::StoreCorrupt),
    }
}

fn prefix_rows(rows: &[JournalRow], frontier: u64) -> Vec<JournalRow> {
    rows.iter()
        .filter(|row| row.seq <= frontier)
        .cloned()
        .collect()
}

/// Read and validate the whole retired layout. Every logical journal field,
/// complete command, migration marker, domain admission and derived family is
/// checked against the actual bytes; the caller receives typed rows only.
pub(crate) async fn read_legacy_store(dir: &Path) -> Result<Option<LegacyStore>, StoreError> {
    let Some(profile) = legacy_profile(dir)? else {
        return Ok(None);
    };
    let connection = lancedb::connect(dir.to_str().ok_or(StoreError::InvalidPath)?)
        .session(crate::connection::native_session())
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let mut names = connection
        .table_names()
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    names.sort();
    let mut expected = vec![
        crate::JOURNAL_TABLE.to_owned(),
        crate::OBJECTS_TABLE.to_owned(),
    ];
    if profile == "L0002" {
        expected.extend([
            crate::RELATIONS_TABLE.to_owned(),
            crate::SEARCH_TABLE.to_owned(),
        ]);
    }
    expected.sort();
    if names != expected {
        return Err(StoreError::StoreCorrupt);
    }

    let journal = connection
        .open_table(crate::JOURNAL_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let journal_version = table_version(&journal).await?;
    let rows = read_journal_rows(&journal).await?;
    if rows.is_empty() {
        return Err(StoreError::StoreCorrupt);
    }
    crate::journal::validate_journal_rows(&rows)?;
    crate::projections::JournalAdmissionState::from_journal_rows(&rows)?;
    let row_profile = crate::writer::journal_profile(&rows)?;
    if row_profile != Some(profile)
        || !crate::migrations::L0001::validate_marker(&rows, true)?
        || crate::migrations::L0002::validate_marker(&rows, profile == "L0002")?
            != (profile == "L0002")
    {
        return Err(StoreError::StoreCorrupt);
    }
    let frontier = rows.last().map(|row| row.seq).unwrap_or(0);
    let complete = complete_command_frontiers(&rows)?;

    let objects = connection
        .open_table(crate::OBJECTS_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let object_version = table_version(&objects).await?;
    let object_rows = read_objects_rows(&objects).await?;
    let object_checkpoint = crate::objects::checkpoint_from_rows(&object_rows)?;
    if object_checkpoint > frontier
        || !(object_checkpoint == 0 || complete.contains(&object_checkpoint))
        || object_rows
            .iter()
            .any(|row| row.source_event_seq > object_checkpoint)
    {
        return Err(StoreError::StoreCorrupt);
    }
    let expected_objects =
        crate::projections::reduce_journal(&prefix_rows(&rows, object_checkpoint))?;
    if sort_objects(expected_objects.rows) != sort_objects(object_rows.clone()) {
        return Err(StoreError::StoreCorrupt);
    }

    let (relation_version, relation_checkpoint, search_version, search_checkpoint) =
        if profile == "L0002" {
            let relations_table = connection
                .open_table(crate::RELATIONS_TABLE)
                .execute()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            let version = table_version(&relations_table).await?;
            let relation_rows = read_relation_rows(&relations_table).await?;
            let checkpoint = crate::relations::checkpoint_from_rows(&relation_rows)?;

            let search_table = connection
                .open_table(crate::SEARCH_TABLE)
                .execute()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            let search_version = table_version(&search_table).await?;
            let indices = search_table
                .list_indices()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            if indices.len() != 1 || indices[0].columns != ["text"] {
                return Err(StoreError::StoreCorrupt);
            }
            let search_rows = crate::search::read_search_rows(&search_table).await?;
            let search_checkpoint = crate::search::read_search_checkpoint(&search_table).await?;
            if checkpoint > frontier
                || !(checkpoint == 0 || complete.contains(&checkpoint))
                || search_checkpoint > frontier
                || !(search_checkpoint == 0 || complete.contains(&search_checkpoint))
                || relation_rows
                    .iter()
                    .any(|row| row.source_event_seq > checkpoint)
                || search_rows
                    .iter()
                    .any(|row| row.source_event_seq > search_checkpoint)
            {
                return Err(StoreError::StoreCorrupt);
            }
            let objects_at = crate::projections::reduce_journal(&prefix_rows(&rows, checkpoint))?;
            let derived = crate::query::derive_l0002_projections(&objects_at)?;
            if sort_relations(derived.relations) != sort_relations(relation_rows) {
                return Err(StoreError::StoreCorrupt);
            }
            let expected_search = if checkpoint == search_checkpoint {
                derived.search
            } else {
                let search_objects =
                    crate::projections::reduce_journal(&prefix_rows(&rows, search_checkpoint))?;
                crate::query::derive_l0002_projections(&search_objects)?.search
            };
            if sort_search(expected_search) != sort_search(search_rows) {
                return Err(StoreError::StoreCorrupt);
            }
            (
                Some(version),
                Some(checkpoint),
                Some(search_version),
                Some(search_checkpoint),
            )
        } else {
            (None, None, None, None)
        };

    Ok(Some(LegacyStore {
        profile,
        rows,
        journal_version,
        object_version,
        relation_version,
        search_version,
        object_checkpoint,
        relation_checkpoint,
        search_checkpoint,
    }))
}

async fn table_version(table: &Table) -> Result<u64, StoreError> {
    let version = table.version().await.map_err(|_| StoreError::LanceDb)?;
    if version == 0 {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(version)
}

async fn read_journal_rows(table: &Table) -> Result<Vec<JournalRow>, StoreError> {
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != crate::journal::journal_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let mut rows = Vec::new();
    for batch in crate::collect_batches(&table.query())
        .await
        .map_err(|_| StoreError::LanceDb)?
    {
        rows.extend(crate::journal::rows_from_batch(&batch)?);
    }
    Ok(rows)
}

async fn read_objects_rows(table: &Table) -> Result<Vec<ObjectRow>, StoreError> {
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != crate::objects::objects_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let mut rows = Vec::new();
    for batch in crate::collect_batches(&table.query())
        .await
        .map_err(|_| StoreError::LanceDb)?
    {
        rows.extend(objects_from_batch(&batch)?);
    }
    Ok(rows)
}

async fn read_relation_rows(table: &Table) -> Result<Vec<RelationProjectionRow>, StoreError> {
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != crate::relations::relations_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let mut rows = Vec::new();
    for batch in crate::collect_batches(&table.query())
        .await
        .map_err(|_| StoreError::LanceDb)?
    {
        rows.extend(relations_from_batch(&batch)?);
    }
    Ok(rows)
}

/// End-of-command frontiers of a validated history. A physical checkpoint is
/// only legal at one of these positions or at zero.
fn complete_command_frontiers(rows: &[JournalRow]) -> Result<BTreeSet<u64>, StoreError> {
    let mut groups: std::collections::BTreeMap<evertrace_domain::ids::CommandId, Vec<u64>> =
        std::collections::BTreeMap::new();
    for row in rows {
        groups.entry(row.command_id).or_default().push(row.seq);
    }
    let mut ends = BTreeSet::new();
    for mut seqs in groups.into_values() {
        seqs.sort_unstable();
        let first = *seqs.first().ok_or(StoreError::StoreCorrupt)?;
        if seqs
            .iter()
            .enumerate()
            .any(|(index, seq)| *seq != first + index as u64)
        {
            return Err(StoreError::StoreCorrupt);
        }
        ends.insert(*seqs.last().ok_or(StoreError::StoreCorrupt)?);
    }
    Ok(ends)
}

fn sort_objects(mut rows: Vec<ObjectRow>) -> Vec<ObjectRow> {
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    rows
}

fn sort_relations(mut rows: Vec<RelationProjectionRow>) -> Vec<RelationProjectionRow> {
    rows.sort();
    rows
}

fn sort_search(mut rows: Vec<SearchProjectionRow>) -> Vec<SearchProjectionRow> {
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    rows
}

fn objects_from_batch(batch: &RecordBatch) -> Result<Vec<ObjectRow>, StoreError> {
    if batch.schema().as_ref() != crate::objects::objects_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let row_ids = string_array(batch, 0)?;
    let row_kinds = string_array(batch, 1)?;
    let row_classes = string_array(batch, 2)?;
    let object_families = string_array(batch, 3)?;
    let object_kinds = string_array(batch, 4)?;
    let object_ids = string_array(batch, 5)?;
    let revisions = string_array(batch, 6)?;
    let lifecycles = string_array(batch, 7)?;
    let epistemics = string_array(batch, 8)?;
    let authorities = string_array(batch, 9)?;
    let publications = string_array(batch, 10)?;
    let supports = string_array(batch, 11)?;
    let projects = string_array(batch, 12)?;
    let repositories = string_array(batch, 13)?;
    let worktrees = string_array(batch, 14)?;
    let tasks = string_array(batch, 15)?;
    let workstreams = string_array(batch, 16)?;
    let sessions = string_array(batch, 17)?;
    let payloads = batch
        .column(18)
        .as_any()
        .downcast_ref::<LargeStringArray>()
        .ok_or(StoreError::StoreCorrupt)?;
    let source_seqs = uint64_array(batch, 19)?;
    let generations = uint64_array(batch, 20)?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        let row = ObjectRow {
            row_id: row_ids.value(index).into(),
            row_kind: ObjectRowKind::parse(row_kinds.value(index))?,
            row_class: optional(row_classes, index)
                .map(ObjectRowClass::parse)
                .transpose()?,
            object_family: optional(object_families, index)
                .map(ObjectFamily::parse)
                .transpose()?,
            object_kind: owned(object_kinds, index),
            object_id: owned(object_ids, index),
            current_revision_id: owned(revisions, index),
            lifecycle: owned(lifecycles, index),
            epistemic: owned(epistemics, index),
            authority: owned(authorities, index),
            publication_state: owned(publications, index),
            support_state: owned(supports, index),
            project_id: owned(projects, index),
            repository_id: owned(repositories, index),
            worktree_id: owned(worktrees, index),
            task_id: owned(tasks, index),
            workstream_id: owned(workstreams, index),
            session_id: owned(sessions, index),
            payload_json: (!payloads.is_null(index)).then(|| payloads.value(index).to_owned()),
            source_event_seq: source_seqs.value(index),
            projection_generation: generations.value(index),
        };
        row.validate()?;
        rows.push(row);
    }
    Ok(rows)
}

fn relations_from_batch(batch: &RecordBatch) -> Result<Vec<RelationProjectionRow>, StoreError> {
    if batch.schema().as_ref() != crate::relations::relations_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let ids = string_array(batch, 0)?;
    let kinds = string_array(batch, 1)?;
    let sources = string_array(batch, 2)?;
    let targets = string_array(batch, 3)?;
    let frontiers = uint64_array(batch, 4)?;
    let generations = uint64_array(batch, 5)?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        let row = RelationProjectionRow {
            row_id: ids.value(index).into(),
            relation_kind: owned(kinds, index),
            source_id: owned(sources, index),
            target_id: owned(targets, index),
            source_event_seq: frontiers.value(index),
            projection_generation: generations.value(index),
        };
        row.validate()?;
        rows.push(row);
    }
    // Checkpoint uniqueness is validated over the whole table by the caller,
    // not over individual batches that may contain only relation edges.
    Ok(rows)
}

fn string_array(batch: &RecordBatch, index: usize) -> Result<&StringArray, StoreError> {
    batch
        .column(index)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or(StoreError::StoreCorrupt)
}

fn uint64_array(batch: &RecordBatch, index: usize) -> Result<&UInt64Array, StoreError> {
    batch
        .column(index)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or(StoreError::StoreCorrupt)
}

fn optional(array: &StringArray, index: usize) -> Option<&str> {
    (!array.is_null(index)).then(|| array.value(index))
}

fn owned(array: &StringArray, index: usize) -> Option<String> {
    optional(array, index).map(str::to_owned)
}

/// Pure encoders for retired-layout test fixtures. This module is never part
/// of a production build and depends on no test framework; the store's own
/// unit tests and the narrow `test_support` export both use these encoders, so
/// there is exactly one serializer for the retired physical shape.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) mod test_format {
    #[cfg(feature = "test-utils")]
    use std::os::unix::fs::DirBuilderExt;
    use std::path::Path;
    use std::sync::Arc;

    use arrow_array::{
        ArrayRef, FixedSizeBinaryArray, LargeStringArray, RecordBatch, StringArray,
        TimestampMicrosecondArray, UInt16Array, UInt64Array,
    };
    use lancedb::index::{Index, scalar::FtsIndexBuilder};

    use crate::command::{ObjectFamily, StoreError};
    use crate::journal::JournalRow;
    use crate::objects::{ObjectRow, ObjectRowClass};
    use crate::relations::RelationProjectionRow;
    use crate::search::SearchProjectionRow;

    pub(crate) fn journal_batch(rows: &[JournalRow]) -> Result<RecordBatch, StoreError> {
        let string =
            |values: Vec<String>| Arc::new(StringArray::from_iter_values(values)) as ArrayRef;
        let option =
            |values: Vec<Option<&str>>| Arc::new(StringArray::from_iter(values)) as ArrayRef;
        let columns: Vec<ArrayRef> = vec![
            string(rows.iter().map(|row| row.event_id.clone()).collect()),
            string(rows.iter().map(|row| row.command_id.to_string()).collect()),
            Arc::new(
                FixedSizeBinaryArray::try_from_iter(
                    rows.iter().map(|row| row.command_hash.as_slice()),
                )
                .map_err(|_| StoreError::Arrow)?,
            ),
            Arc::new(UInt16Array::from_iter_values(
                rows.iter().map(|row| row.ordinal),
            )),
            Arc::new(UInt16Array::from_iter_values(
                rows.iter().map(|row| row.command_event_count),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.seq),
            )),
            string(rows.iter().map(|row| row.event_type.clone()).collect()),
            string(
                rows.iter()
                    .map(|row| row.record_class.as_str().into())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.object_family.map(|family| family.as_str()))
                    .collect(),
            ),
            option(rows.iter().map(|row| row.object_id.as_deref()).collect()),
            option(rows.iter().map(|row| row.revision_id.as_deref()).collect()),
            option(
                rows.iter()
                    .map(|row| row.scope.project_id.as_deref())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.scope.repository_id.as_deref())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.scope.worktree_id.as_deref())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.scope.task_id.as_deref())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.scope.workstream_id.as_deref())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.scope.session_id.as_deref())
                    .collect(),
            ),
            option(
                rows.iter()
                    .map(|row| row.scope.execution_lane_id.as_deref())
                    .collect(),
            ),
            Arc::new(
                TimestampMicrosecondArray::from_iter_values(
                    rows.iter().map(|row| row.occurred_at_us),
                )
                .with_timezone("UTC"),
            ),
            Arc::new(
                TimestampMicrosecondArray::from_iter_values(
                    rows.iter().map(|row| row.ingested_at_us),
                )
                .with_timezone("UTC"),
            ),
            string(
                rows.iter()
                    .map(|row| row.source_kind.as_str().into())
                    .collect(),
            ),
            Arc::new(LargeStringArray::from_iter(
                rows.iter().map(|row| row.source_ref_json.as_deref()),
            )),
            Arc::new(UInt16Array::from_iter_values(
                rows.iter().map(|row| row.payload_schema),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                rows.iter().map(|row| row.payload_json.as_str()),
            )),
            Arc::new(
                FixedSizeBinaryArray::try_from_iter(
                    rows.iter().map(|row| row.content_hash.as_slice()),
                )
                .map_err(|_| StoreError::Arrow)?,
            ),
            option(rows.iter().map(|row| row.causation_id.as_deref()).collect()),
            option(
                rows.iter()
                    .map(|row| row.correlation_id.as_deref())
                    .collect(),
            ),
            Arc::new(
                FixedSizeBinaryArray::try_from_iter(
                    rows.iter().map(|row| row.effective_config_hash.as_slice()),
                )
                .map_err(|_| StoreError::Arrow)?,
            ),
            string(
                rows.iter()
                    .map(|row| row.algorithm_revision.clone())
                    .collect(),
            ),
        ];
        RecordBatch::try_new(crate::journal::journal_schema(), columns)
            .map_err(|_| StoreError::Arrow)
    }

    pub(crate) fn objects_batch(rows: &[ObjectRow]) -> Result<RecordBatch, StoreError> {
        for row in rows {
            row.validate()?;
        }
        let string =
            |values: Vec<Option<&str>>| Arc::new(StringArray::from_iter(values)) as ArrayRef;
        let columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.row_id.as_str()),
            )),
            Arc::new(StringArray::from_iter_values(
                rows.iter().map(|row| row.row_kind.as_str()),
            )),
            string(
                rows.iter()
                    .map(|row| row.row_class.map(ObjectRowClass::as_str))
                    .collect(),
            ),
            string(
                rows.iter()
                    .map(|row| row.object_family.map(ObjectFamily::as_str))
                    .collect(),
            ),
            string(rows.iter().map(|row| row.object_kind.as_deref()).collect()),
            string(rows.iter().map(|row| row.object_id.as_deref()).collect()),
            string(
                rows.iter()
                    .map(|row| row.current_revision_id.as_deref())
                    .collect(),
            ),
            string(rows.iter().map(|row| row.lifecycle.as_deref()).collect()),
            string(rows.iter().map(|row| row.epistemic.as_deref()).collect()),
            string(rows.iter().map(|row| row.authority.as_deref()).collect()),
            string(
                rows.iter()
                    .map(|row| row.publication_state.as_deref())
                    .collect(),
            ),
            string(
                rows.iter()
                    .map(|row| row.support_state.as_deref())
                    .collect(),
            ),
            string(rows.iter().map(|row| row.project_id.as_deref()).collect()),
            string(
                rows.iter()
                    .map(|row| row.repository_id.as_deref())
                    .collect(),
            ),
            string(rows.iter().map(|row| row.worktree_id.as_deref()).collect()),
            string(rows.iter().map(|row| row.task_id.as_deref()).collect()),
            string(
                rows.iter()
                    .map(|row| row.workstream_id.as_deref())
                    .collect(),
            ),
            string(rows.iter().map(|row| row.session_id.as_deref()).collect()),
            Arc::new(LargeStringArray::from_iter(
                rows.iter().map(|row| row.payload_json.as_deref()),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.source_event_seq),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.projection_generation),
            )),
        ];
        RecordBatch::try_new(crate::objects::objects_schema(), columns)
            .map_err(|_| StoreError::Arrow)
    }

    pub(crate) fn relations_batch(
        rows: &[RelationProjectionRow],
    ) -> Result<RecordBatch, StoreError> {
        for row in rows {
            row.validate()?;
        }
        RecordBatch::try_new(
            crate::relations::relations_schema(),
            vec![
                Arc::new(StringArray::from_iter_values(
                    rows.iter().map(|row| row.row_id.as_str()),
                )) as ArrayRef,
                Arc::new(StringArray::from_iter(
                    rows.iter().map(|row| row.relation_kind.as_deref()),
                )),
                Arc::new(StringArray::from_iter(
                    rows.iter().map(|row| row.source_id.as_deref()),
                )),
                Arc::new(StringArray::from_iter(
                    rows.iter().map(|row| row.target_id.as_deref()),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|row| row.source_event_seq),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|row| row.projection_generation),
                )),
            ],
        )
        .map_err(|_| StoreError::Arrow)
    }

    pub(crate) async fn write_tables(
        native: &Path,
        profile: &str,
        rows: &[JournalRow],
        objects: &[ObjectRow],
        relations: &[RelationProjectionRow],
        search: &[SearchProjectionRow],
    ) {
        let connection = lancedb::connect(native.to_str().unwrap())
            .session(crate::connection::native_session())
            .execute()
            .await
            .unwrap();
        connection
            .create_table(crate::JOURNAL_TABLE, journal_batch(rows).unwrap())
            .execute()
            .await
            .unwrap();
        connection
            .create_table(crate::OBJECTS_TABLE, objects_batch(objects).unwrap())
            .execute()
            .await
            .unwrap();
        if profile == "L0002" {
            connection
                .create_table(crate::RELATIONS_TABLE, relations_batch(relations).unwrap())
                .execute()
                .await
                .unwrap();
            let table = connection
                .create_table(
                    crate::SEARCH_TABLE,
                    crate::search::search_batch(search).unwrap(),
                )
                .execute()
                .await
                .unwrap();
            let params = FtsIndexBuilder::default()
                .base_tokenizer("icu".into())
                .stem(false)
                .remove_stop_words(false)
                .ascii_folding(true)
                .with_position(false);
            table
                .create_index(&["text"], Index::FTS(params))
                .execute()
                .await
                .unwrap();
        }
    }

    /// Materialize one valid retired layout from already-persisted logical
    /// rows. `root` is a caller-owned empty test container; the function only
    /// creates the requested tables (canonical `store/` or flat) and never
    /// deletes or converts an existing store.
    #[cfg(feature = "test-utils")]
    pub(crate) async fn write_legacy_fixture(
        root: &Path,
        canonical: bool,
        profile: &str,
        rows: &[JournalRow],
    ) -> Result<(), StoreError> {
        if !matches!(profile, "L0001" | "L0002") || rows.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let metadata = std::fs::symlink_metadata(root).map_err(|_| StoreError::Io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(StoreError::InvalidInput);
        }
        crate::journal::validate_journal_rows(rows)?;
        crate::projections::JournalAdmissionState::from_journal_rows(rows)?;
        if crate::writer::journal_profile(rows)? != Some(profile) {
            return Err(StoreError::InvalidInput);
        }
        let native = if canonical {
            let native = root.join("store");
            match std::fs::symlink_metadata(&native) {
                Ok(_) => return Err(StoreError::InvalidInput),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(StoreError::Io),
            }
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&native)
                .map_err(|_| StoreError::Io)?;
            native
        } else {
            root.to_owned()
        };
        let snapshot = crate::projections::reduce_journal(rows)?;
        let (relations, search) = if profile == "L0002" {
            let derived = crate::query::derive_l0002_projections(&snapshot)?;
            (derived.relations, derived.search)
        } else {
            (Vec::new(), Vec::new())
        };
        write_tables(&native, profile, rows, &snapshot.rows, &relations, &search).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    use evertrace_capture::{RecoveryGateMode, RecoverySnapshotSettings, SpoolLimits};
    use evertrace_domain::ids::{CommandId, TaskId};
    use evertrace_domain::revision::RevisionId;
    use evertrace_domain::work::{
        Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership,
    };
    use lancedb::index::{Index, scalar::FtsIndexBuilder};

    use super::*;
    use crate::backup::{BackupFrozenBoundary, BackupHookBoundary};
    use crate::command::{DirtyTarget, DirtyTargetKind, prepare_command};
    use crate::journal::rows_for_append;
    use crate::legacy_lance::test_format::{journal_batch, relations_batch, write_tables};
    use crate::{JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot};

    #[test]
    fn relation_batches_validate_one_checkpoint_across_the_whole_table() {
        let edge = RelationProjectionRow::edge(
            "repository_to_worktree",
            3,
            "repository".into(),
            "worktree".into(),
        );
        let checkpoint = RelationProjectionRow::checkpoint(3);
        let data_batch = relations_batch(std::slice::from_ref(&edge)).unwrap();
        let checkpoint_batch = relations_batch(std::slice::from_ref(&checkpoint)).unwrap();

        let mut rows = relations_from_batch(&data_batch).unwrap();
        assert!(matches!(
            crate::relations::checkpoint_from_rows(&rows),
            Err(StoreError::StoreCorrupt)
        ));
        rows.extend(relations_from_batch(&checkpoint_batch).unwrap());
        assert_eq!(rows, vec![edge, checkpoint]);
        assert_eq!(crate::relations::checkpoint_from_rows(&rows).unwrap(), 3);

        rows.extend(relations_from_batch(&checkpoint_batch).unwrap());
        assert!(matches!(
            crate::relations::checkpoint_from_rows(&rows),
            Err(StoreError::StoreCorrupt)
        ));
    }

    fn migration_command(command_id: &str, migration_id: &str) -> JournalCommand {
        JournalCommand::new(
            CommandId::from_str(command_id).unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                migration_id.to_ascii_lowercase(),
                JournalPayload::MigrationApplied(crate::command::MigrationApplied {
                    migration_id: migration_id.into(),
                }),
            )],
        )
        .unwrap()
    }

    fn task_command(goal: &str, at: i64) -> JournalCommand {
        let task = Task {
            task_id: TaskId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: vec![format!("request-{goal}")],
            canonical_goal: goal.into(),
            scope_memberships: vec![TaskScopeMembership {
                repository_instance_id: None,
                worktree_instance_ids: Vec::new(),
            }],
            identity_confidence: TaskIdentityConfidence::Explicit,
            lifecycle: TaskLifecycle::Active,
            continuation_of_task_id: None,
            split_from_task_id: None,
            split_into_task_ids: Vec::new(),
            merged_from_task_ids: Vec::new(),
            merged_into_task_id: None,
            created_at_us: at,
            closed_at_us: None,
            source_watermark: 1,
        };
        JournalCommand::new(
            CommandId::new_v7(),
            vec![
                JournalEventDraft::runtime(
                    at,
                    [9; 32],
                    "legacy-converter-fixture",
                    JournalPayload::TaskRecorded(Box::new(task)),
                ),
                JournalEventDraft::runtime(
                    at,
                    [9; 32],
                    "legacy-converter-fixture",
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::ObjectsProjection,
                        target_id: goal.into(),
                        algorithm_revision: "objects-projection-v1".into(),
                        source_watermark: 1,
                    }),
                ),
            ],
        )
        .unwrap()
    }

    fn push(rows: &mut Vec<JournalRow>, command: &JournalCommand, seq: &mut u64, gap: u64) {
        *seq = seq.checked_add(gap.max(1)).unwrap();
        let prepared = prepare_command(command).unwrap();
        let new = rows_for_append(&prepared, *seq, 11).unwrap();
        *seq = new.last().unwrap().seq;
        rows.extend(new);
    }

    struct Fixture {
        data: PathBuf,
        config: PathBuf,
        rows: Vec<JournalRow>,
        snapshot: ProjectionSnapshot,
        relations: Vec<RelationProjectionRow>,
        search: Vec<SearchProjectionRow>,
        object_checkpoint: u64,
    }

    async fn stage(
        canonical: bool,
        profile: &'static str,
        backlog: bool,
        gap: u64,
        big_seq: bool,
    ) -> (tempfile::TempDir, Fixture) {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let fixture = stage_at(&data, canonical, profile, backlog, gap, big_seq).await;
        (temp, fixture)
    }

    async fn stage_at(
        data: &Path,
        canonical: bool,
        profile: &'static str,
        backlog: bool,
        gap: u64,
        big_seq: bool,
    ) -> Fixture {
        std::fs::DirBuilder::new().mode(0o700).create(data).unwrap();
        let mut rows = Vec::new();
        let mut seq = if big_seq { 1_u64 << 63 } else { 0 };
        push(
            &mut rows,
            &migration_command("01890f47-6a4a-7cc1-98b9-01890f476a40", "L0001"),
            &mut seq,
            1,
        );
        push(&mut rows, &task_command("alpha goal", 21), &mut seq, gap);
        let first_end = rows.last().unwrap().seq;
        push(&mut rows, &task_command("beta goal", 22), &mut seq, 1);
        if profile == "L0002" {
            push(
                &mut rows,
                &migration_command("01890f47-6a4a-7cc1-98b9-01890f476a41", "L0002"),
                &mut seq,
                1,
            );
        }
        let frontier = rows.last().unwrap().seq;
        let snapshot = crate::projections::reduce_journal(&rows).unwrap();
        assert_eq!(snapshot.frontier, frontier);
        let object_checkpoint = if backlog { first_end } else { frontier };
        let prefix = rows
            .iter()
            .filter(|row| row.seq <= object_checkpoint)
            .cloned()
            .collect::<Vec<_>>();
        let objects = crate::projections::reduce_journal(&prefix).unwrap();
        let (relations, search) = if profile == "L0002" {
            let derived = crate::query::derive_l0002_projections(&objects).unwrap();
            (derived.relations, derived.search)
        } else {
            (Vec::new(), Vec::new())
        };
        let native = if canonical {
            let native = data.join("store");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&native)
                .unwrap();
            native
        } else {
            data.to_owned()
        };
        write_tables(&native, profile, &rows, &objects.rows, &relations, &search).await;

        evertrace_capture::CasStore::open(data.join("cas")).unwrap();
        let settings = data.join("settings");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&settings)
            .unwrap();
        let config = settings.join("config.toml");
        let effective = evertrace_domain::config::EffectiveConfig::default();
        let config_hash = effective.hash();
        let bytes = effective.to_toml().unwrap();
        std::fs::write(&config, bytes.as_bytes()).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let runtime = evertrace_capture::RuntimeSnapshot::for_data_dir(
            data,
            7,
            SpoolLimits {
                high_watermark_bytes: 4096,
                low_watermark_bytes: 2048,
                max_main_files: 4,
                emergency_slots: 2,
            },
            RecoverySnapshotSettings {
                gate: RecoveryGateMode::Disabled,
                preflight_timeout_ms: 100,
                effective_config_hash: config_hash,
                adapter_manifest_id: None,
                classifier_revision: 1,
                max_bundle_bytes: 4096,
                max_untracked_file_bytes: 1024,
                max_untracked_total_bytes: 2048,
                recall_cue_gate: evertrace_capture::RecallCueGateMode::Disabled,
                recall_cue_adapter_manifest_id: None,
            },
        )
        .unwrap();
        runtime
            .publish(&evertrace_capture::RuntimeSnapshot::snapshot_path(data))
            .unwrap();
        Fixture {
            data: data.to_owned(),
            config,
            rows,
            snapshot,
            relations,
            search,
            object_checkpoint,
        }
    }

    fn empty_hook() -> Result<BackupHookBoundary, crate::BackupError> {
        Ok(BackupHookBoundary {
            current_generation: None,
            retained_generations: Vec::new(),
            pin_count: 0,
            pinned_generation_count: 0,
            files: Vec::new(),
        })
    }

    /// Bounded byte-level snapshot of a fixture tree. File *content* is
    /// compared, not only the file size, so "unchanged" claims are about the
    /// actual bytes.
    fn tree_bytes(root: &Path) -> Vec<(String, Vec<u8>)> {
        tree_snapshot(root, |_| false)
    }

    fn tree_snapshot(root: &Path, skip: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
        const MAX_FIXTURE_FILE_BYTES: u64 = 16 * 1024 * 1024;
        let mut entries = Vec::new();
        let mut pending = vec![root.to_owned()];
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    pending.push(entry.path());
                } else {
                    let relative = entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned();
                    if skip(&relative) {
                        continue;
                    }
                    assert!(metadata.len() <= MAX_FIXTURE_FILE_BYTES);
                    let bytes = std::fs::read(entry.path()).unwrap();
                    assert_eq!(bytes.len() as u64, metadata.len());
                    entries.push((relative, bytes));
                }
            }
        }
        entries.sort();
        entries
    }

    async fn legacy_v2_backup(fixture: &Fixture) -> PathBuf {
        let legacy = read_legacy_store(&fixture.data.join("store"))
            .await
            .unwrap()
            .unwrap();
        let runtime = evertrace_capture::RuntimeSnapshot::load(
            &evertrace_capture::RuntimeSnapshot::snapshot_path(&fixture.data),
        )
        .unwrap();
        let fence = evertrace_capture::MaintenanceFence::open(&fixture.data).unwrap();
        let (mut spool, _) = evertrace_capture::DurableSpool::open(
            runtime.spool_dir.clone(),
            runtime.spool_limits().unwrap(),
        )
        .unwrap();
        let guard = fence.exclusive().unwrap();
        let spool_boundary = spool
            .freeze_backup_boundary(&guard, runtime.generation)
            .unwrap();
        drop(guard);
        drop(spool);
        let id = evertrace_domain::ids::JobId::new_v7();
        let plan = crate::backup::prepare_backup(
            (&fixture.data, &fixture.data.join("store")),
            (&fixture.config, &runtime),
            id,
            &legacy.full_snapshot().unwrap(),
            legacy.table_states(),
            crate::backup::BackupShape::Legacy {
                compiler_watermark: legacy.object_checkpoint,
            },
            BackupFrozenBoundary {
                spool: spool_boundary,
                hook: empty_hook().unwrap(),
            },
        )
        .unwrap();
        let staging = crate::backup::stage_backup(plan).unwrap();
        let summary = crate::backup::verify_staged_backup(&staging).await.unwrap();
        crate::backup::publish_backup(staging, summary).unwrap();
        fixture.data.join(format!("backups/backup-{id}"))
    }

    #[tokio::test]
    async fn legacy_live_store_restores_from_a_v2_backup_into_a_candidate() {
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        let backup = legacy_v2_backup(&fixture).await;
        let config_hash = evertrace_domain::config::EffectiveConfig::default().hash();
        let prepared =
            crate::restore::prepare(&fixture.data, &backup, 1_000, config_hash, |_, _| Ok(()))
                .await
                .unwrap();
        let crate::restore::RestorePreparation::Candidate(candidate) = prepared else {
            panic!("a legacy live store must convert into a candidate");
        };
        assert_eq!(candidate.full_projection().await.unwrap(), fixture.snapshot);
        // The candidate is a new-format closed-layout copy: authoritative
        // SQLite plus the search projection, with no retired Lance tables.
        let native = candidate.path().join("store");
        assert!(native.join("evertrace.sqlite").is_file());
        assert!(
            !native
                .join(format!("{}.lance", crate::JOURNAL_TABLE))
                .exists()
        );
        assert!(
            !native
                .join(format!("{}.lance", crate::OBJECTS_TABLE))
                .exists()
        );
        // The live retired layout is only read; it is never moved or rewritten.
        assert!(
            fixture
                .data
                .join("store")
                .join(format!("{}.lance", crate::JOURNAL_TABLE))
                .is_dir()
        );
        let _ = candidate.discard(crate::restore::RestoreError::Io);

        // Without a current deletion ledger this remains an independently
        // verifiable historical copy, not a converted live candidate.
        let absent_live = fixture
            .data
            .parent()
            .unwrap()
            .join("without-current-ledger");
        let historical =
            crate::restore::prepare(&absent_live, &backup, 1_001, config_hash, |_, _| Ok(()))
                .await
                .unwrap();
        let crate::restore::RestorePreparation::Historical { directory } = historical else {
            panic!("missing live authority must remain historical");
        };
        let verification = crate::backup::prepare_verification_directory(&directory, None).unwrap();
        crate::backup::complete_backup_verification_ref(&verification)
            .await
            .unwrap();
        assert!(!directory.join("store/evertrace.sqlite").exists());
        assert_eq!(
            read_legacy_store(&directory.join("store"))
                .await
                .unwrap()
                .unwrap()
                .rows,
            fixture.rows
        );
    }

    #[tokio::test]
    async fn canonical_l0002_converts_with_equal_rows_markers_and_nonempty_fts() {
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        let outcome =
            crate::restore::upgrade_native(&fixture.data, &fixture.config, empty_hook, |_, _| {
                Ok(())
            })
            .await
            .unwrap();
        let crate::restore::NativeUpgradeOutcome::Published {
            backup,
            migrated,
            retained_native,
        } = outcome
        else {
            panic!("a retired layout must publish a converted store");
        };
        assert!(!migrated);
        assert!(retained_native.is_empty());

        // The pre-upgrade backup is an independently verified v2 snapshot that
        // still carries the original logical rows and physical versions.
        let verification = crate::backup::prepare_verification_directory(&backup, None).unwrap();
        crate::backup::complete_backup_verification_ref(&verification)
            .await
            .unwrap();
        assert_eq!(verification.manifest_version(), 2);
        let stored = read_legacy_store(&backup.join("store"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.profile, "L0002");
        assert_eq!(stored.rows, fixture.rows);
        assert_eq!(stored.object_checkpoint, fixture.object_checkpoint);

        let writer = crate::JournalWriter::open(&fixture.data).await.unwrap();
        assert_eq!(writer.journal_rows().await.unwrap(), fixture.rows);
        assert_eq!(writer.full_projection().await.unwrap(), fixture.snapshot);
        assert_eq!(writer.relation_rows().await.unwrap(), fixture.relations);
        assert_eq!(writer.search_rows().await.unwrap(), fixture.search);
        drop(writer);

        let index = crate::search::SearchIndex::open(&fixture.data)
            .await
            .unwrap();
        assert!(
            !index.fts("alpha").await.unwrap().is_empty(),
            "converted store must carry the real FTS index"
        );
    }

    #[tokio::test]
    async fn flat_l0001_converts_with_one_forward_marker_and_retained_residue() {
        let (_temp, fixture) = stage(false, "L0001", false, 1, false).await;
        let outcome =
            crate::restore::upgrade_native(&fixture.data, &fixture.config, empty_hook, |_, _| {
                Ok(())
            })
            .await
            .unwrap();
        let crate::restore::NativeUpgradeOutcome::Published {
            backup, migrated, ..
        } = outcome
        else {
            panic!("flat L0001 must publish");
        };
        assert!(migrated);
        let writer = crate::JournalWriter::open(&fixture.data).await.unwrap();
        let rows = writer.journal_rows().await.unwrap();
        assert_eq!(rows.len(), fixture.rows.len() + 1);
        assert_eq!(&rows[..fixture.rows.len()], fixture.rows.as_slice());
        let last = rows.last().unwrap();
        assert_eq!(last.seq, fixture.rows.last().unwrap().seq + 1);
        assert!(matches!(
            last.payload().unwrap(),
            JournalPayload::MigrationApplied(ref value) if value.migration_id == "L0002"
        ));
        assert!(
            fixture.rows.iter().any(|row| matches!(
                row.payload().unwrap(),
                JournalPayload::MigrationApplied(ref value) if value.migration_id == "L0001"
            )),
            "the original L0001 marker must be preserved"
        );
        // The original flat closure was retired only after the candidate was
        // published, and the backup keeps the untouched L0001 shape.
        for table in [
            crate::JOURNAL_TABLE,
            crate::OBJECTS_TABLE,
            crate::RELATIONS_TABLE,
            crate::SEARCH_TABLE,
        ] {
            assert!(!fixture.data.join(format!("{table}.lance")).exists());
        }
        let stored = read_legacy_store(&backup.join("store"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.profile, "L0001");
        assert_eq!(stored.rows, fixture.rows);
        drop(writer);
        let index = crate::search::SearchIndex::open(&fixture.data)
            .await
            .unwrap();
        assert!(!index.fts("beta").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn object_backlog_seq_gap_and_cross_i64_convert_without_renumbering() {
        let (_temp, fixture) = stage(true, "L0002", true, 5, true).await;
        assert!(fixture.rows.last().unwrap().seq > i64::MAX as u64);
        assert!(fixture.object_checkpoint < fixture.rows.last().unwrap().seq);
        // Native families publish independently: search may have reached the
        // frontier while objects and relations still contain a valid prefix.
        let derived = crate::query::derive_l0002_projections(&fixture.snapshot).unwrap();
        {
            let connection = lancedb::connect(fixture.data.join("store").to_str().unwrap())
                .session(crate::connection::native_session())
                .execute()
                .await
                .unwrap();
            connection
                .drop_table(crate::SEARCH_TABLE, &[])
                .await
                .unwrap();
            let table = connection
                .create_table(
                    crate::SEARCH_TABLE,
                    crate::search::search_batch(&derived.search).unwrap(),
                )
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
        }
        let outcome =
            crate::restore::upgrade_native(&fixture.data, &fixture.config, empty_hook, |_, _| {
                Ok(())
            })
            .await
            .unwrap();
        let crate::restore::NativeUpgradeOutcome::Published { backup, .. } = outcome else {
            panic!("a lagging legacy projection must convert");
        };
        let manifest: crate::BackupManifest =
            serde_json::from_slice(&std::fs::read(backup.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest.manifest_version, 2);
        assert_eq!(manifest.compiler_watermark, fixture.object_checkpoint);
        assert!(manifest.compiler_watermark < manifest.frontier);
        assert_eq!(
            manifest.table_states.relations.as_ref().unwrap().checkpoint,
            fixture.object_checkpoint
        );
        assert_eq!(
            manifest.table_states.search.as_ref().unwrap().checkpoint,
            fixture.rows.last().unwrap().seq
        );
        let verification = crate::backup::prepare_verification_directory(&backup, None).unwrap();
        crate::backup::complete_backup_verification_ref(&verification)
            .await
            .unwrap();

        let writer = crate::JournalWriter::open(&fixture.data).await.unwrap();
        assert_eq!(writer.journal_rows().await.unwrap(), fixture.rows);
        assert_eq!(writer.full_projection().await.unwrap(), fixture.snapshot);
        // The conversion rebuilds the derived families at the full frontier,
        // past the lagging legacy checkpoint, without renumbering history.
        assert_eq!(writer.relation_rows().await.unwrap(), derived.relations);
        assert_eq!(writer.search_rows().await.unwrap(), derived.search);
    }

    #[tokio::test]
    async fn corrupt_projection_and_partial_layout_are_refused_without_touching_the_source() {
        // A physical projection that disagrees with its own verified history is
        // refused before any backup or candidate exists.
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        let native = fixture.data.join("store");
        let connection = lancedb::connect(native.to_str().unwrap())
            .session(crate::connection::native_session())
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        objects.delete("row_kind = 'data'").await.unwrap();
        let before = tree_bytes(&native);
        let result = crate::restore::prepare_native_upgrade(
            &fixture.data,
            &fixture.config,
            empty_hook,
            |_, _| Ok(()),
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::restore::RestoreError::Store(
                StoreError::StoreCorrupt
            ))
        ));
        assert_eq!(tree_bytes(&native), before);
        assert!(!fixture.data.join("backups").exists());

        // A partial retired layout (relations without search) is corruption,
        // and the surviving tables are untouched.
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        let native = fixture.data.join("store");
        std::fs::remove_dir_all(native.join(format!("{}.lance", crate::SEARCH_TABLE))).unwrap();
        let before = tree_bytes(&native);
        let result = crate::restore::prepare_native_upgrade(
            &fixture.data,
            &fixture.config,
            empty_hook,
            |_, _| Ok(()),
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::restore::RestoreError::Store(
                StoreError::StoreCorrupt
            ))
        ));
        assert_eq!(tree_bytes(&native), before);
    }

    #[tokio::test]
    async fn forged_l0002_marker_without_canonical_command_is_refused() {
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        let native = fixture.data.join("store");
        // The canonical validation helper must reject a marker name carried by
        // a different command. Build the forged command through the same
        // production admission path and append it to the old journal.
        let forged = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a42").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "l0002",
                JournalPayload::MigrationApplied(crate::command::MigrationApplied {
                    migration_id: "L0002".into(),
                }),
            )],
        )
        .unwrap();
        let prepared = prepare_command(&forged).unwrap();
        let extra = rows_for_append(&prepared, fixture.rows.last().unwrap().seq + 1, 11).unwrap();
        let mut rows = fixture.rows.clone();
        rows.extend(extra);
        let connection = lancedb::connect(native.to_str().unwrap())
            .session(crate::connection::native_session())
            .execute()
            .await
            .unwrap();
        connection
            .drop_table(crate::JOURNAL_TABLE, &[])
            .await
            .unwrap();
        connection
            .create_table(crate::JOURNAL_TABLE, journal_batch(&rows).unwrap())
            .execute()
            .await
            .unwrap();
        let result = read_legacy_store(&native).await;
        assert!(matches!(result, Err(StoreError::StoreCorrupt)));
    }

    fn tables_bytes(data: &Path, canonical: bool) -> Vec<(String, Vec<u8>)> {
        let root = if canonical {
            data.join("store")
        } else {
            data.to_owned()
        };
        let mut rows = Vec::new();
        for table in [
            crate::JOURNAL_TABLE,
            crate::OBJECTS_TABLE,
            crate::RELATIONS_TABLE,
            crate::SEARCH_TABLE,
        ] {
            let path = root.join(format!("{table}.lance"));
            for (relative, bytes) in tree_bytes(&path) {
                rows.push((format!("{table}.lance/{relative}"), bytes));
            }
        }
        rows.sort();
        rows
    }

    /// Bytes of the durable inputs that must never move during publication:
    /// CAS, spool, config, runtime, keys and hook assets. Store containers,
    /// backups and upgrade candidates are compared explicitly elsewhere.
    fn durable_inputs(data: &Path) -> Vec<(String, Vec<u8>)> {
        tree_snapshot(data, |relative| {
            relative.starts_with("store/")
                || relative.starts_with("backups/")
                || relative.starts_with(".upgrade-")
        })
    }

    /// Lance creates files and directories with default modes; a backup tree is
    /// expected to be owner-private. Normalize only inside the mutated test
    /// copy before rehashing it.
    fn make_tree_private(root: &Path) {
        let mut pending = vec![root.to_owned()];
        while let Some(path) = pending.pop() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            for entry in std::fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    pending.push(entry.path());
                } else {
                    std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
            }
        }
    }

    /// Re-executed as a real child process. `lock` holds the sibling writer
    /// lock; the checkpoint modes exit hard at one named publication boundary,
    /// exactly like a process crash.
    #[tokio::test]
    async fn native_publication_process_child() {
        let Some(mode) = std::env::var_os("EVERTRACE_STORE_UPGRADE_CHILD") else {
            return;
        };
        let mode = mode.to_string_lossy().into_owned();
        let data = PathBuf::from(std::env::var_os("EVERTRACE_STORE_UPGRADE_DATA").unwrap());
        let config = PathBuf::from(std::env::var_os("EVERTRACE_STORE_UPGRADE_CONFIG").unwrap());
        if mode == "probe-lock" {
            assert!(matches!(
                crate::SiblingWriterLock::acquire(&data),
                Err(StoreError::WriterAlreadyRunning)
            ));
            return;
        }
        if mode == "lock" {
            let _held = crate::SiblingWriterLock::acquire(&data).expect("child must hold lock");
            std::fs::write(data.join("child-ready"), b"ready").unwrap();
            let release = data.join("child-release");
            let deadline = Instant::now() + Duration::from_secs(60);
            while !release.exists() {
                assert!(Instant::now() < deadline, "lock child was never released");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            return;
        }
        let exit_code = match mode.as_str() {
            "prepared" => 71,
            "published" => 72,
            "durable" => 73,
            other => panic!("unknown child mode {other}"),
        };
        crate::restore::upgrade_native_inner(&data, &config, empty_hook, |_, _| Ok(()), &|point| {
            use crate::restore::NativePublicationPoint;
            let reached = match point {
                NativePublicationPoint::Prepared => "prepared",
                NativePublicationPoint::Published => "published",
                NativePublicationPoint::Durable => "durable",
                NativePublicationPoint::BackupFrozen => "backup-frozen",
            };
            if reached == mode {
                std::process::exit(exit_code);
            }
            Ok(())
        })
        .await
        .expect("child publication");
        panic!("child never reached {mode}");
    }

    #[tokio::test]
    async fn real_process_exits_leave_only_complete_or_fail_closed_states() {
        for canonical in [true, false] {
            for mode in ["prepared", "published", "durable"] {
                let temp = tempfile::tempdir().unwrap();
                let data = temp.path().join("data");
                let fixture = stage_at(&data, canonical, "L0002", false, 1, false).await;
                let source_before = tables_bytes(&data, canonical);
                let durable_before = durable_inputs(&data);

                let code = match mode {
                    "prepared" => 71,
                    "published" => 72,
                    _ => 73,
                };
                let status = Command::new(std::env::current_exe().unwrap())
                    .arg("--exact")
                    .arg("legacy_lance::tests::native_publication_process_child")
                    .arg("--nocapture")
                    .env("EVERTRACE_STORE_UPGRADE_CHILD", mode)
                    .env("EVERTRACE_STORE_UPGRADE_DATA", &data)
                    .env("EVERTRACE_STORE_UPGRADE_CONFIG", &fixture.config)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap();
                assert_eq!(
                    status.code(),
                    Some(code),
                    "canonical={canonical} mode={mode}"
                );

                let backup = std::fs::read_dir(data.join("backups"))
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("backup-")
                    })
                    .expect("the pre-upgrade v2 backup must exist");
                let backup_count_before = std::fs::read_dir(data.join("backups")).unwrap().count();
                let backup_before = tree_bytes(&backup);

                let restarted =
                    crate::restore::upgrade_native(&data, &fixture.config, empty_hook, |_, _| {
                        Ok(())
                    })
                    .await;

                if mode == "prepared" {
                    // Nothing was published: no empty authority, the source
                    // container is intact and the residual candidate is
                    // explicitly refused instead of adopted or deleted.
                    assert!(matches!(
                        restarted,
                        Err(crate::restore::RestoreError::ResidualCandidate { .. })
                    ));
                    assert!(matches!(
                        crate::JournalWriter::open(&data).await,
                        Err(StoreError::UpgradeRequired)
                    ));
                    let candidate = std::fs::read_dir(&data)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| {
                            path.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".upgrade-")
                        })
                        .expect("the prepared candidate must be preserved");
                    assert!(candidate.join("evertrace.sqlite").is_file());
                    if canonical {
                        assert!(!data.join("store/evertrace.sqlite").exists());
                    } else {
                        assert!(!data.join("store").exists());
                    }
                } else {
                    // A complete canonical authority exists and reopens with the
                    // original journal rows, unchanged and un-renumbered.
                    assert!(data.join("store/evertrace.sqlite").is_file());
                    if canonical {
                        // A preserved residual makes every writer/publication
                        // entry fail closed, so the published authority is read
                        // with the read-only verifier instead.
                        let verified =
                            crate::backup::read_verified_store_tables(&data.join("store"))
                                .await
                                .unwrap();
                        assert_eq!(verified.journal_rows, fixture.rows);
                        assert_eq!(
                            crate::projections::reduce_journal(&verified.journal_rows).unwrap(),
                            fixture.snapshot
                        );
                    } else {
                        let writer = crate::JournalWriter::open(&data).await.unwrap();
                        assert_eq!(writer.journal_rows().await.unwrap(), fixture.rows);
                        assert_eq!(writer.full_projection().await.unwrap(), fixture.snapshot);
                        drop(writer);
                    }
                    if canonical {
                        // The retired container now lives at the preserved
                        // candidate locator and must remain byte-identical; the
                        // restart fails closed rather than deleting it.
                        let residual = std::fs::read_dir(&data)
                            .unwrap()
                            .map(|entry| entry.unwrap().path())
                            .find(|path| {
                                path.file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .starts_with(".upgrade-")
                            })
                            .expect("the exchanged old container must be preserved");
                        assert!(
                            tree_bytes(&residual) == source_before,
                            "canonical={canonical} mode={mode}: exchanged container changed"
                        );
                        assert!(matches!(
                            restarted,
                            Err(crate::restore::RestoreError::ResidualCandidate { .. })
                        ));
                    } else {
                        let crate::restore::NativeUpgradeOutcome::Noop { retained_native } =
                            restarted.unwrap()
                        else {
                            panic!("a published flat container must restart as a complete no-op");
                        };
                        assert_eq!(retained_native.len(), 4);
                        for path in &retained_native {
                            assert!(path.is_dir(), "{}", path.display());
                        }
                    }
                }

                if canonical && mode != "prepared" {
                    // Already compared against the preserved candidate container.
                } else {
                    assert!(
                        tables_bytes(&data, canonical) == source_before,
                        "canonical={canonical} mode={mode}: original table bytes changed"
                    );
                }
                assert!(
                    durable_inputs(&data) == durable_before,
                    "canonical={canonical} mode={mode}: durable inputs changed"
                );
                assert!(
                    tree_bytes(&backup) == backup_before,
                    "canonical={canonical} mode={mode}: backup bytes changed"
                );
                assert_eq!(
                    std::fs::read_dir(data.join("backups")).unwrap().count(),
                    backup_count_before
                );
            }
        }
    }

    #[tokio::test]
    async fn sibling_writer_lock_is_held_across_real_processes() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let fixture = stage_at(&data, true, "L0002", false, 1, false).await;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("legacy_lance::tests::native_publication_process_child")
            .arg("--nocapture")
            .env("EVERTRACE_STORE_UPGRADE_CHILD", "lock")
            .env("EVERTRACE_STORE_UPGRADE_DATA", &data)
            .env("EVERTRACE_STORE_UPGRADE_CONFIG", &fixture.config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let ready = data.join("child-ready");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "child never acquired the lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(matches!(
            crate::SiblingWriterLock::acquire(&data),
            Err(StoreError::WriterAlreadyRunning)
        ));
        let refused =
            crate::restore::upgrade_native(&data, &fixture.config, empty_hook, |_, _| Ok(())).await;
        assert!(matches!(
            refused,
            Err(crate::restore::RestoreError::Store(
                StoreError::WriterAlreadyRunning
            ))
        ));
        assert!(!data.join("backups").exists());
        std::fs::write(data.join("child-release"), b"release").unwrap();
        assert!(child.wait().unwrap().success());
        // The old lock holder has exited. Now prove that the actual prepared
        // converter owns the same exclusion across a second process until it
        // performs the original publication.
        let prepared =
            crate::restore::prepare_native_upgrade(&data, &fixture.config, empty_hook, |_, _| {
                Ok(())
            })
            .await
            .unwrap();
        let crate::restore::NativeUpgradePreparation::Prepared(prepared) = prepared else {
            panic!("retired layout must produce a native candidate");
        };
        let blocked = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("legacy_lance::tests::native_publication_process_child")
            .env("EVERTRACE_STORE_UPGRADE_CHILD", "probe-lock")
            .env("EVERTRACE_STORE_UPGRADE_DATA", &data)
            .env("EVERTRACE_STORE_UPGRADE_CONFIG", &fixture.config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            blocked.success(),
            "second process acquired the converter lock"
        );
        let published = prepared
            .publish_package(|| crate::restore::PackagePublication::Committed)
            .await
            .unwrap();
        assert!(matches!(
            published,
            crate::restore::NativeUpgradeOutcome::Published { .. }
        ));
        let writer = crate::JournalWriter::open(&data).await.unwrap();
        assert_eq!(writer.journal_rows().await.unwrap(), fixture.rows);
    }

    fn command_from_rows(rows: &[JournalRow]) -> JournalCommand {
        let mut ordered = rows.to_vec();
        ordered.sort_by_key(|row| row.ordinal);
        JournalCommand::new(
            ordered[0].command_id,
            ordered
                .iter()
                .map(|row| JournalEventDraft {
                    occurred_at_us: row.occurred_at_us,
                    source_kind: row.source_kind,
                    scope: row.scope.clone(),
                    causation_id: row.causation_id.clone(),
                    correlation_id: row.correlation_id.clone(),
                    effective_config_hash: row.effective_config_hash,
                    algorithm_revision: row.algorithm_revision.clone(),
                    payload: row.payload().unwrap(),
                })
                .collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn converted_history_replays_the_original_multi_event_command() {
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        // Hold the same materialized command from before the format switch;
        // conversion must not require reconstructing a new retry identity.
        let original = command_from_rows(&fixture.rows[1..3]);
        assert_eq!(original.events().len(), 2);
        assert_eq!(original.command_id(), fixture.rows[1].command_id);
        let outcome =
            crate::restore::upgrade_native(&fixture.data, &fixture.config, empty_hook, |_, _| {
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            crate::restore::NativeUpgradeOutcome::Published { .. }
        ));
        for pass in 0..2 {
            let mut writer = crate::JournalWriter::open(&fixture.data).await.unwrap();
            let rows_before = writer.journal_rows().await.unwrap();
            assert_eq!(rows_before, fixture.rows);
            let frontier_before = writer.full_projection().await.unwrap().frontier;
            let committed = writer.commit(&original, 11).await.unwrap();
            assert!(committed.replayed, "pass {pass} must be a lost-ACK replay");
            assert_eq!(committed.first_seq, fixture.rows[1].seq);
            assert_eq!(committed.last_seq, fixture.rows[2].seq);
            assert_eq!(
                committed.event_ids,
                fixture.rows[1..3]
                    .iter()
                    .map(|row| row.event_id.clone())
                    .collect::<Vec<_>>()
            );
            assert_eq!(writer.journal_rows().await.unwrap(), rows_before);
            assert_eq!(
                writer.full_projection().await.unwrap().frontier,
                frontier_before
            );
        }
    }

    #[tokio::test]
    async fn rehashed_v2_backup_semantic_corruption_is_refused() {
        let (_temp, fixture) = stage(true, "L0002", false, 1, false).await;
        let backup = legacy_v2_backup(&fixture).await;
        let control = legacy_v2_backup(&fixture).await;
        let control_before = tree_bytes(&control);
        let verification = crate::backup::prepare_verification_directory(&control, None).unwrap();
        crate::backup::complete_backup_verification_ref(&verification)
            .await
            .unwrap();
        let live_before = tree_bytes(&fixture.data.join("store"));

        let native = backup.join("store");
        let version = {
            let connection = lancedb::connect(native.to_str().unwrap())
                .session(crate::connection::native_session())
                .execute()
                .await
                .unwrap();
            let objects = connection
                .open_table(crate::OBJECTS_TABLE)
                .execute()
                .await
                .unwrap();
            let updated = objects
                .update()
                .only_if("row_kind = 'data'")
                .column("payload_json", "'{\"corrupted\":true}'")
                .execute()
                .await
                .unwrap();
            assert!(updated.rows_updated > 0);
            updated.version
        };
        // Rehash only the mutated native closure and record the actual new
        // table version, exactly like the real inventory path would.
        let manifest_path = backup.join("manifest.json");
        let mut manifest: crate::BackupManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let mut files = manifest
            .files
            .iter()
            .filter(|file| !file.relative_path.starts_with("store"))
            .cloned()
            .collect::<Vec<_>>();
        make_tree_private(&native);
        files.extend(crate::backup::native_upgrade_manifest(&native).unwrap());
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        manifest.files = files;
        manifest.table_states.objects.version = Some(version);
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        // File-level verification actually succeeds; only the semantic check
        // refuses the mismatch.
        let verification = crate::backup::prepare_verification_directory(&backup, None).unwrap();
        assert!(matches!(
            crate::backup::complete_backup_verification_ref(&verification).await,
            Err(crate::BackupError::Corrupt)
        ));
        // The live source and the untouched control backup stay verifiable and
        // byte-identical.
        assert!(
            tree_bytes(&fixture.data.join("store")) == live_before,
            "the live source must not be touched by backup hashing"
        );
        let verification = crate::backup::prepare_verification_directory(&control, None).unwrap();
        crate::backup::complete_backup_verification_ref(&verification)
            .await
            .unwrap();
        assert!(
            tree_bytes(&control) == control_before,
            "control backup bytes must stay unchanged"
        );
    }
}
