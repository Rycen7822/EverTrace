use std::{fs, path::PathBuf};

use evertrace_store::{
    CompatibilityStore, ProbeRow, probe_batch, probe_schema, schema_fingerprint,
};
use tempfile::TempDir;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn published_profile_matches_pinned_identity_and_single_schema_fingerprint() {
    let text = fs::read_to_string(root().join("program/store-profile.toml")).unwrap();
    let profile: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(profile["status"].as_str(), Some("passed"));
    assert_eq!(profile["rust_release"].as_str(), Some("1.97.1"));
    assert_eq!(profile["lancedb_version"].as_str(), Some("0.37.1"));
    assert_eq!(profile["dependencies"]["lance"].as_str(), Some("10.0.0"));
    assert_eq!(
        profile["dependencies"]["datafusion"].as_str(),
        Some("54.1.0")
    );
    assert_eq!(
        profile["probe_schema"]["canonical_fingerprint"].as_str(),
        Some(
            schema_fingerprint(probe_schema().as_ref())
                .unwrap()
                .as_str()
        )
    );
    assert_eq!(text.matches("canonical_fingerprint").count(), 1);
    assert!(!text.contains("evertrace_journal"));
    assert!(!text.contains("L0001"));
    assert!(!text.contains("L0002"));
}

#[test]
fn profile_freezes_visibility_prune_snapshot_concurrency_and_negative_results() {
    let text = fs::read_to_string(root().join("program/store-profile.toml")).unwrap();
    let profile: toml::Value = toml::from_str(&text).unwrap();
    for key in [
        "local_connect_create_open",
        "merge_insert_insert_if_absent",
        "merge_insert_matched_update_disabled",
        "fts_indexed_and_unindexed_visibility",
        "table_version_list_checkout_restore",
        "conservative_prune",
        "exclusive_aggressive_prune",
        "handles_closed_directory_snapshot",
        "snapshot_independent_reopen",
        "crash_reopen",
        "concurrent_reads_one_writer",
        "second_process_commit_visibility",
        "schema_mismatch_rejected",
        "missing_manifest_rejected",
        "malformed_manifest_isolated",
    ] {
        assert_eq!(profile["verified"][key].as_bool(), Some(true), "{key}");
    }
    assert_eq!(profile["fts"]["base_tokenizer"].as_str(), Some("icu"));
    assert_eq!(
        profile["fts"]["delta_fallback_required"].as_bool(),
        Some(false)
    );
    assert_eq!(profile["scalar_index"]["approved"].as_bool(), Some(false));
    assert_eq!(profile["scalar_index"]["kind"].as_str(), Some("none"));
    assert!(
        profile["scalar_index"]["columns"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        profile["scalar_index"]["decision"].as_str(),
        Some("no S06 benchmark proved a scalar index necessary")
    );
    assert_eq!(
        profile["concurrency"]["lancedb_enforces_evertrace_single_writer"].as_bool(),
        Some(false)
    );
    assert_eq!(
        profile["concurrency"]["evertrace_sibling_writer_lock_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        profile["characterization"]["fixed_cross_machine_threshold"].as_bool(),
        Some(false)
    );
    let unsupported = profile["unsupported_behavior"].as_array().unwrap();
    assert!(
        unsupported
            .iter()
            .any(|item| { item["key"].as_str() == Some("malformed_short_manifest_direct_open") })
    );
}

#[tokio::test]
async fn profile_helpers_create_only_isolated_probe_tables() {
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    let batch = probe_batch(&[ProbeRow {
        id: 1,
        command_id: "contract-1",
        text: "mixed 检索 contract",
        generation: 1,
    }])
    .unwrap();
    let table = store
        .create_probe_table("probe_testkit", batch)
        .await
        .unwrap();
    assert_eq!(table.count_rows(None).await.unwrap(), 1);
    assert_eq!(
        store.connection().table_names().execute().await.unwrap(),
        vec!["probe_testkit"]
    );

    let fixture =
        fs::read_to_string(root().join("fixtures/store/lancedb_compat/cases.toml")).unwrap();
    let fixture: toml::Value = toml::from_str(&fixture).unwrap();
    assert_eq!(fixture["fixture_version"].as_integer(), Some(1));
    assert!(fixture["cases"].as_array().unwrap().len() >= 10);
}
