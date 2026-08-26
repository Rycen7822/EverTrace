use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Instant,
};

use arrow_array::{Int64Array, RecordBatch, RecordBatchIterator, StringArray};
use arrow_schema::{DataType, Field, Schema};
use evertrace_store::{
    CompatibilityStore, ProbeRow, collect_batches, probe_batch, probe_schema, schema_fingerprint,
};
use lancedb::{
    Table,
    index::{
        Index,
        scalar::{FtsIndexBuilder, FullTextSearchQuery},
    },
    query::{QueryBase, Select},
    table::{CompactionOptions, OptimizeAction},
};
use tempfile::TempDir;

const CHILD_MODE: &str = "EVERTRACE_S06_CHILD_MODE";
const CHILD_STORE: &str = "EVERTRACE_S06_CHILD_STORE";

fn rows(values: &[(i64, &str, &str, i64)]) -> RecordBatch {
    let values = values
        .iter()
        .map(|(id, command, text, generation)| ProbeRow {
            id: *id,
            command_id: command,
            text,
            generation: *generation,
        })
        .collect::<Vec<_>>();
    probe_batch(&values).unwrap()
}

async fn add(table: &Table, batch: RecordBatch) {
    table.add(batch).execute().await.unwrap();
}

fn reader(batch: RecordBatch) -> Box<dyn arrow_array::RecordBatchReader + Send> {
    Box::new(RecordBatchIterator::new(vec![Ok(batch)], probe_schema()))
}

fn count_batches(batches: &[RecordBatch]) -> usize {
    batches.iter().map(RecordBatch::num_rows).sum()
}

#[tokio::test]
async fn local_create_open_add_filter_select_count_and_schema_contract() {
    let started = Instant::now();
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    let table = store
        .create_probe_table(
            "probe_core",
            rows(&[
                (1, "cmd-1", "alpha memory", 1),
                (2, "cmd-2", "beta 检索", 1),
            ]),
        )
        .await
        .unwrap();
    assert_eq!(
        store.connection().table_names().execute().await.unwrap(),
        vec!["probe_core"]
    );
    assert_eq!(table.count_rows(None).await.unwrap(), 2);
    assert_eq!(
        table
            .count_rows(Some("id = 2 AND generation = 1".into()))
            .await
            .unwrap(),
        1
    );
    let selected = collect_batches(&table.query().select(Select::columns(&["id", "text"])))
        .await
        .unwrap();
    assert_eq!(count_batches(&selected), 2);
    assert_eq!(selected[0].num_columns(), 2);
    let reopened = store.open_probe_table("probe_core").await.unwrap();
    assert_eq!(reopened.count_rows(None).await.unwrap(), 2);
    assert_eq!(
        reopened.schema().await.unwrap().as_ref(),
        probe_schema().as_ref()
    );

    let wrong_schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("command_id", DataType::Utf8, false),
        Field::new("text", DataType::Utf8, false),
        Field::new("generation", DataType::Utf8, false),
    ]));
    let wrong = RecordBatch::try_new(
        wrong_schema,
        vec![
            Arc::new(Int64Array::from(vec![3])),
            Arc::new(StringArray::from(vec!["cmd-3"])),
            Arc::new(StringArray::from(vec!["wrong"])),
            Arc::new(StringArray::from(vec!["one"])),
        ],
    )
    .unwrap();
    assert!(table.add(wrong).execute().await.is_err());
    println!(
        "S06_CORE latency_ms={} rss_kib={} schema_fingerprint={}",
        started.elapsed().as_millis(),
        current_rss_kib().unwrap_or(0),
        schema_fingerprint(probe_schema().as_ref()).unwrap()
    );
}

#[tokio::test]
async fn merge_insert_is_insert_only_and_exact_query_detects_retries() {
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    let table = store
        .create_probe_table("probe_merge", rows(&[(1, "command-a", "original", 1)]))
        .await
        .unwrap();
    let before = table.version().await.unwrap();
    let mut merge = table.merge_insert(&["id"]);
    merge.when_not_matched_insert_all();
    let result = merge
        .execute(reader(rows(&[
            (1, "command-a", "must-not-update", 2),
            (2, "command-b", "inserted", 1),
        ])))
        .await
        .unwrap();
    assert_eq!(result.num_inserted_rows, 1);
    assert_eq!(result.num_updated_rows, 0);
    assert_eq!(table.version().await.unwrap(), before + 1);
    assert_eq!(table.count_rows(None).await.unwrap(), 2);
    assert_eq!(
        table
            .count_rows(Some(
                "id = 1 AND text = 'original' AND generation = 1".into()
            ))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        table
            .count_rows(Some("command_id = 'command-a'".into()))
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn mixed_language_fts_sees_indexed_and_latest_unindexed_rows() {
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    let table = store
        .create_probe_table(
            "probe_fts",
            rows(&[
                (1, "fts-1", "Rust memory retrieval", 1),
                (2, "fts-2", "中文记忆检索", 1),
            ]),
        )
        .await
        .unwrap();
    let params = FtsIndexBuilder::default()
        .base_tokenizer("icu".into())
        .stem(false)
        .remove_stop_words(false)
        .with_position(false);
    table
        .create_index(&["text"], Index::FTS(params))
        .execute()
        .await
        .unwrap();
    assert_eq!(table.list_indices().await.unwrap().len(), 1);
    let english = collect_batches(
        &table
            .query()
            .full_text_search(FullTextSearchQuery::new("retrieval".into())),
    )
    .await
    .unwrap();
    let chinese = collect_batches(
        &table
            .query()
            .full_text_search(FullTextSearchQuery::new("检索".into())),
    )
    .await
    .unwrap();
    assert_eq!(count_batches(&english), 1);
    assert_eq!(count_batches(&chinese), 1);

    add(&table, rows(&[(3, "fts-3", "latest 检索 delta", 2)])).await;
    let visible = collect_batches(
        &table
            .query()
            .full_text_search(FullTextSearchQuery::new("检索".into())),
    )
    .await
    .unwrap();
    assert_eq!(count_batches(&visible), 2);
    let indexed_only = collect_batches(
        &table
            .query()
            .full_text_search(FullTextSearchQuery::new("检索".into()))
            .fast_search(),
    )
    .await
    .unwrap();
    assert_eq!(count_batches(&indexed_only), 1);
    table
        .optimize(OptimizeAction::Index(Default::default()))
        .await
        .unwrap();
    let optimized = collect_batches(
        &table
            .query()
            .full_text_search(FullTextSearchQuery::new("检索".into()))
            .fast_search(),
    )
    .await
    .unwrap();
    assert_eq!(count_batches(&optimized), 2);
}

#[tokio::test]
async fn versions_restore_delete_compact_prune_snapshot_and_independent_reopen() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let store = CompatibilityStore::connect_local(&source).await.unwrap();
    let table = store
        .create_probe_table("probe_versions", rows(&[(1, "v-1", "one", 1)]))
        .await
        .unwrap();
    let first_version = table.version().await.unwrap();
    add(&table, rows(&[(2, "v-2", "two", 1)])).await;
    assert!(table.list_versions().await.unwrap().len() >= 2);
    table.checkout(first_version).await.unwrap();
    assert_eq!(table.count_rows(None).await.unwrap(), 1);
    table.restore().await.unwrap();
    assert_eq!(table.count_rows(None).await.unwrap(), 1);
    add(&table, rows(&[(3, "v-3", "three", 1)])).await;
    table.delete("id = 3").await.unwrap();
    assert_eq!(table.count_rows(None).await.unwrap(), 1);
    table
        .optimize(OptimizeAction::Compact {
            options: CompactionOptions::default(),
            remap_options: None,
        })
        .await
        .unwrap();
    let versions_before_conservative = table.list_versions().await.unwrap().len();
    table
        .optimize(OptimizeAction::Prune {
            older_than: Some(Default::default()),
            delete_unverified: Some(false),
            error_if_tagged_old_versions: Some(true),
        })
        .await
        .unwrap();
    let versions_after_conservative = table.list_versions().await.unwrap().len();
    assert!(versions_after_conservative >= 1);
    assert!(versions_after_conservative < versions_before_conservative);
    drop(table);
    drop(store);

    let snapshot = temp.path().join("snapshot");
    copy_directory(&source, &snapshot);
    let source_store = CompatibilityStore::connect_local(&source).await.unwrap();
    let snapshot_store = CompatibilityStore::connect_local(&snapshot).await.unwrap();
    let source_table = source_store
        .open_probe_table("probe_versions")
        .await
        .unwrap();
    let snapshot_table = snapshot_store
        .open_probe_table("probe_versions")
        .await
        .unwrap();
    assert_eq!(source_table.count_rows(None).await.unwrap(), 1);
    assert_eq!(snapshot_table.count_rows(None).await.unwrap(), 1);
    add(&source_table, rows(&[(4, "v-4", "source-only", 1)])).await;
    assert_eq!(source_table.count_rows(None).await.unwrap(), 2);
    assert_eq!(snapshot_table.count_rows(None).await.unwrap(), 1);
    drop(source_table);
    drop(snapshot_table);
    drop(source_store);
    drop(snapshot_store);

    let exclusive = CompatibilityStore::connect_local(&source).await.unwrap();
    let exclusive_table = exclusive.open_probe_table("probe_versions").await.unwrap();
    let versions_before_aggressive = exclusive_table.list_versions().await.unwrap().len();
    exclusive_table
        .optimize(OptimizeAction::Prune {
            older_than: Some(Default::default()),
            delete_unverified: Some(true),
            error_if_tagged_old_versions: Some(true),
        })
        .await
        .unwrap();
    assert!(exclusive_table.list_versions().await.unwrap().len() < versions_before_aggressive);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_one_writer_crash_reopen_and_true_second_process() {
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    let table = store
        .create_probe_table("probe_process", rows(&[(1, "p-1", "one", 1)]))
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let reader = table.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..8 {
                assert!(reader.count_rows(None).await.unwrap() >= 1);
            }
        }));
    }
    let writer = table.clone();
    tasks.push(tokio::spawn(async move {
        add(&writer, rows(&[(2, "p-2", "two", 1)])).await;
    }));
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(table.count_rows(None).await.unwrap(), 2);

    let status = Command::new(env::current_exe().unwrap())
        .args(["--exact", "second_process_probe_entry", "--nocapture"])
        .env(CHILD_MODE, "write_and_exit")
        .env(CHILD_STORE, temp.path())
        .status()
        .unwrap();
    assert!(status.success());
    drop(table);
    drop(store);
    let reopened = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .open_probe_table("probe_process")
            .await
            .unwrap()
            .count_rows(None)
            .await
            .unwrap(),
        3
    );
}

#[tokio::test]
async fn second_process_probe_entry() {
    let Ok(mode) = env::var(CHILD_MODE) else {
        return;
    };
    let root = PathBuf::from(env::var_os(CHILD_STORE).unwrap());
    let store = CompatibilityStore::connect_local(&root).await.unwrap();
    if mode == "open_corrupt" {
        store.open_probe_table("probe_malformed").await.unwrap();
        panic!("malformed manifest unexpectedly opened");
    }
    assert_eq!(mode, "write_and_exit");
    let table = store.open_probe_table("probe_process").await.unwrap();
    add(&table, rows(&[(3, "p-3", "child-process", 1)])).await;
    assert_eq!(table.count_rows(Some("id = 3".into())).await.unwrap(), 1);
    std::process::exit(0);
}

#[tokio::test]
async fn corrupt_derived_probe_table_fails_open() {
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    let missing_table = store
        .create_probe_table("probe_corrupt", rows(&[(1, "c-1", "one", 1)]))
        .await
        .unwrap();
    let malformed_table = store
        .create_probe_table("probe_malformed", rows(&[(1, "m-1", "one", 1)]))
        .await
        .unwrap();
    drop(missing_table);
    drop(malformed_table);
    drop(store);
    let missing_manifest = first_manifest(&temp.path().join("probe_corrupt.lance/_versions"));
    fs::remove_file(missing_manifest).unwrap();
    let reopened = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    assert!(reopened.open_probe_table("probe_corrupt").await.is_err());

    let malformed_manifest = first_manifest(&temp.path().join("probe_malformed.lance/_versions"));
    fs::write(malformed_manifest, b"corrupt-derived-probe").unwrap();
    let status = Command::new(env::current_exe().unwrap())
        .args(["--exact", "second_process_probe_entry", "--nocapture"])
        .env(CHILD_MODE, "open_corrupt")
        .env(CHILD_STORE, temp.path())
        .status()
        .unwrap();
    assert!(!status.success());
}

fn first_manifest(versions: &Path) -> PathBuf {
    fs::read_dir(versions)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_file())
        .unwrap()
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn current_rss_kib() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}
