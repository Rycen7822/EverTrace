use std::{fs, path::PathBuf};

use evertrace_codex::{ProbeContext, ProbeEvidence};

pub fn fixture_text(name: &str) -> String {
    let path = fixture_path(name);
    fs::read_to_string(path).expect("host probe fixture must be readable")
}

pub fn fixture(name: &str) -> ProbeEvidence {
    let value: serde_json::Value =
        serde_json::from_str(&fixture_text(name)).expect("host probe fixture must be valid JSON");
    ProbeEvidence::from_json(&value["evidence"].to_string())
        .expect("host probe evidence must be valid")
}

pub fn fixture_context(name: &str) -> ProbeContext {
    let value: serde_json::Value =
        serde_json::from_str(&fixture_text(name)).expect("host probe fixture must be valid JSON");
    serde_json::from_value(value["context"].clone()).expect("probe context must be valid")
}

fn fixture_path(name: &str) -> PathBuf {
    assert!(matches!(name, "empty" | "complete"));
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/codex/host_probe")
        .join(format!("{name}.json"))
}
