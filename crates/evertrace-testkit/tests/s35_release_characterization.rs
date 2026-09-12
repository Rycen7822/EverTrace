//! Release evidence collection is deliberately separate from Cargo execution.
//! Run the ignored collector only after the four final commands have exited.
use std::{fs, path::PathBuf};

use evertrace_codex::{
    HostProbeReport,
    probe::{GateResult, ProbeContext, ProbeEvidence},
};
use evertrace_domain::{
    config::EffectiveConfig,
    query::{GateStatus, RetrievalLayer, production_retrieval_layer, retrieval_gate},
};
use evertrace_protocol::mcp::tool_definition;
use serde_json::{Value, json};

const CORPUS: &str = include_str!("../../../fixtures/release/corpus.json");

fn recorded_result(log: &str, test: &str, expected: &str) -> bool {
    let Some((_, rest)) = log.split_once(&format!("test {test} ... ")) else {
        return false;
    };
    // Child daemon stderr can appear between the harness prefix and `ok`.
    // Stop at the next test/result boundary; never borrow another case's pass.
    rest.starts_with(expected)
        || rest
            .lines()
            .take_while(|line| !line.starts_with("test "))
            .any(|line| line == expected)
}

#[test]
fn case_receipts_preserve_interleaved_output_and_do_not_borrow_success() {
    assert!(recorded_result(
        "test doctor ... daemon starting\nok\ntest next ... ok\n",
        "doctor",
        "ok"
    ));
    assert!(!recorded_result(
        "test doctor ... FAILED\ntest next ... ok\n",
        "doctor",
        "ok"
    ));
    assert!(!recorded_result(
        "test doctor ... ignored\ntest result: ok. 0 passed\n",
        "doctor",
        "ok"
    ));
}

fn boundaries() -> Value {
    let report =
        HostProbeReport::evaluate(&ProbeContext::unobserved_codex(), &ProbeEvidence::empty())
            .unwrap();
    let host: Vec<_> = [report.capture(), report.recovery(), report.active_search_due(), report.strong_normalization(), report.project_policy()]
        .into_iter().map(|gate| {
            assert_eq!(gate.result(), GateResult::Disabled);
            json!({"gate": gate.gate_kind(), "status": "not_run", "reason": gate.reason(),
                "evidence": "No authenticated live Host canary authorized or invoked in this characterization",
                "manifest": report.manifest(), "probe": gate})
        }).collect();
    assert!(!report.recovery_barrier_active());
    assert_eq!(production_retrieval_layer(), RetrievalLayer::A);
    assert_eq!(
        evertrace_engine::procedure::procedure_effect_gate(),
        GateStatus::NotCharacterized
    );
    assert_eq!(retrieval_gate(RetrievalLayer::A), GateStatus::Passed);
    for layer in [
        RetrievalLayer::B,
        RetrievalLayer::C,
        RetrievalLayer::D,
        RetrievalLayer::E,
    ] {
        assert_eq!(retrieval_gate(layer), GateStatus::NotCharacterized);
    }
    let schema = tool_definition();
    assert_eq!(schema["name"], "evertrace");
    assert_eq!(
        schema["inputSchema"]["properties"]["action"]["enum"],
        json!(["search", "get", "add", "organize"])
    );
    assert_eq!(schema["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        schema["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .len(),
        4
    );
    let mut file = EffectiveConfig::default().config().clone();
    file.llm.enabled = false;
    let serialized = EffectiveConfig::new(file).unwrap().to_toml().unwrap();
    let config = EffectiveConfig::parse_toml(&serialized).unwrap();
    assert!(!config.config().llm.enabled);
    assert!(
        EffectiveConfig::parse_toml(&format!(
            "{serialized}\n[release_override]\nenabled = true\n"
        ))
        .is_err()
    );
    json!({"host": host, "mcp_schema": schema, "production_retrieval_layer": "A",
    "release_quality_r_star": null,
    "a_f": [
        {"layer":"A","status":"not_run","reason":"No authorized fixed model, judge and paired task budget; deterministic correctness is a separate result"},
        {"layer":"B","status":"not_run","reason":"A release quality uncharacterized; operator remains closed"},
        {"layer":"C","status":"not_run","reason":"B not passed; operator remains closed"},
        {"layer":"D","status":"not_run","reason":"C not passed; operator remains closed"},
        {"layer":"E","status":"not_run","reason":"D not passed; operator remains closed"},
        {"layer":"F","status":"not_run","reason":"No measured R* or authorized same-anchor model comparison; effect gate remains closed"}
    ]})
}

#[test]
fn release_boundaries_do_not_promote_unobserved_host_or_quality() {
    boundaries();
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    assert_eq!(corpus["version"], 1);
    assert_eq!(corpus["baseline_version"], 63);
}

#[test]
#[ignore = "requires completed final command receipts; run the compiled test executable after baseline validation"]
fn collect_completed_release_evidence() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let evidence = PathBuf::from(
        std::env::var_os("EVERTRACE_RELEASE_EVIDENCE").expect("explicit evidence directory"),
    );
    let allowed = root
        .join("target/evertrace-program/release-evidence")
        .canonicalize()
        .unwrap();
    assert!(evidence.canonicalize().unwrap().starts_with(allowed));
    let receipts: Value =
        serde_json::from_slice(&fs::read(evidence.join("commands.json")).unwrap()).unwrap();
    let commands = receipts.as_array().unwrap();
    let expected = [
        "cargo +1.97.1 fmt --all -- --check",
        "cargo +1.97.1 clippy --locked --workspace --all-targets --all-features -- -D warnings",
        "cargo +1.97.1 test --locked --workspace --all-targets --all-features",
        "conda run -n test python tools/check_architecture_baseline.py . --expected-version 63",
    ];
    assert_eq!(commands.len(), expected.len());
    for (receipt, command) in commands.iter().zip(expected) {
        assert_eq!(receipt["command"], command);
        assert_eq!(receipt["exit"], 0, "final command did not pass: {command}");
        let log = receipt["log"].as_str().unwrap();
        assert!(!log.contains('/') && !log.contains(".."));
        assert!(evidence.join(log).is_file());
    }
    let workspace =
        fs::read_to_string(evidence.join(commands[2]["log"].as_str().unwrap())).unwrap();
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let test = case["test"].as_str().unwrap();
        let result = if case["expected"] == "ignored" {
            "ignored"
        } else {
            "ok"
        };
        assert!(
            recorded_result(&workspace, test, result),
            "missing actual {result} case: {test}"
        );
    }
    let suites: Vec<_> = workspace
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    assert!(!suites.is_empty());
    // Nested S06 failure demonstrations can print FAILED. Preserve every result;
    // the completed outer Cargo exit is authoritative, not a substring heuristic.
    let mut output = boundaries();
    output["commands"] = receipts;
    output["suite_results_including_nested_fault_children"] = json!(suites);
    output["corpus"] = corpus;
    assert!(evidence.join("release-characterization.md").is_file());
    output["report"] = json!("release-characterization.md");
    output["scope"] = json!(
        "Local verification evidence only; final acceptance is determined by the orchestrator; no release or publication"
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("manifest.json"))
        .unwrap();
    serde_json::to_writer_pretty(&mut file, &output).unwrap();
    file.sync_all().unwrap();
}
