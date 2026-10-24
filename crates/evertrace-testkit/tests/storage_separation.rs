//! Physical-layout acceptance for the isolated store: one SQLite database is
//! authoritative and Lance keeps only the search projection.

use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JOURNAL_TABLE, JournalCommand, JournalEventDraft, JournalPayload,
    JournalWriter, OBJECTS_TABLE, OutboxEntry, RELATIONS_TABLE, SEARCH_TABLE, StoreError,
};
use tempfile::TempDir;

fn command(seed: u8, target: &str) -> JournalCommand {
    let dirty = DirtyTarget {
        target_kind: DirtyTargetKind::ObjectsProjection,
        target_id: target.into(),
        algorithm_revision: "objects-projection-v1".into(),
        source_watermark: 1,
    };
    JournalCommand::new(
        evertrace_domain::ids::CommandId::new_v7(),
        vec![
            JournalEventDraft::runtime(
                0,
                [seed; 32],
                "objects-projection-v1",
                JournalPayload::DirtyTarget(dirty.clone()),
            ),
            JournalEventDraft::runtime(
                0,
                [seed; 32],
                "objects-projection-v1",
                JournalPayload::OutboxEnqueued(OutboxEntry {
                    outbox_id: format!("outbox-{target}"),
                    dirty,
                }),
            ),
        ],
    )
    .unwrap()
}

#[tokio::test]
async fn fresh_store_uses_one_sqlite_database_and_search_only_lance() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    writer
        .commit(&command(0xa1, "separation-one"), 1)
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();

    let native = evertrace_store::connection::native_root(&root);
    assert!(native.join("evertrace.sqlite").is_file());
    assert!(native.join(format!("{SEARCH_TABLE}.lance")).is_dir());
    for table in [JOURNAL_TABLE, OBJECTS_TABLE, RELATIONS_TABLE] {
        assert!(!root.join(format!("{table}.lance")).exists());
        assert!(!native.join(format!("{table}.lance")).exists());
    }
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![SEARCH_TABLE.to_owned()]
    );
    assert_eq!(writer.object_rows().await.unwrap(), snapshot.rows);
    assert!(!writer.relation_rows().await.unwrap().is_empty());
    assert!(!writer.search_rows().await.unwrap().is_empty());

    drop(writer);
    let reopened = JournalWriter::open(&root).await.unwrap();
    assert_eq!(reopened.full_projection().await.unwrap(), snapshot);
    assert_eq!(reopened.object_rows().await.unwrap(), snapshot.rows);
    drop(reopened);

    // Derived search is not authority for a new journal. A missing database
    // must fail without creating a replacement beside the existing index.
    std::fs::remove_file(native.join("evertrace.sqlite")).unwrap();
    assert!(matches!(
        JournalWriter::open(&root).await,
        Err(StoreError::StoreCorrupt)
    ));
    assert!(!native.join("evertrace.sqlite").exists());
}

#[tokio::test]
async fn every_retired_lance_table_is_refused_from_both_locators() {
    use std::os::unix::fs::DirBuilderExt;
    for (label, canonical) in [("flat", false), ("canonical", true)] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("store");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let native = if canonical {
            let native = root.join("store");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&native)
                .unwrap();
            native
        } else {
            root.clone()
        };
        let legacy = native.join(format!("{JOURNAL_TABLE}.lance"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&legacy)
            .unwrap();
        std::fs::write(legacy.join("data.lance"), b"retired").unwrap();
        assert!(
            matches!(
                JournalWriter::open(&root).await,
                Err(StoreError::UpgradeRequired)
            ),
            "{label} layout must require the offline converter"
        );
        assert_eq!(
            std::fs::read(legacy.join("data.lance")).unwrap(),
            b"retired",
            "{label} layout must be left byte-for-byte untouched"
        );
        assert!(!native.join("evertrace.sqlite").exists());
    }
}

#[tokio::test]
async fn external_checkpoint_gap_fails_closed_until_objects_are_rebuilt() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    writer
        .commit(&command(0xb2, "separation-gap"), 1)
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    drop(writer);

    evertrace_store::test_support::advance_object_checkpoint(&root).unwrap();
    assert!(
        matches!(
            JournalWriter::open(&root).await,
            Err(StoreError::StoreCorrupt)
        ),
        "a checkpoint beyond the persisted journal must fail closed"
    );

    evertrace_store::test_support::clear_objects(&root).unwrap();
    let rebuilt = JournalWriter::open(&root).await.unwrap();
    assert_eq!(
        rebuilt.object_rows().await.unwrap(),
        snapshot.rows,
        "the journal must rebuild the objects family"
    );
    assert_eq!(rebuilt.full_projection().await.unwrap(), snapshot);
}

#[tokio::test]
async fn a_second_writer_is_refused_and_the_first_keeps_the_store() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    assert!(matches!(
        JournalWriter::open(&root).await,
        Err(StoreError::WriterAlreadyRunning)
    ));
    writer
        .commit(&command(0xc3, "separation-lock"), 1)
        .await
        .unwrap();
    assert_eq!(writer.journal_rows().await.unwrap().len(), 4);
}
