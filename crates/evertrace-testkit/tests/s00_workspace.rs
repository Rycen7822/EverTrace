use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[test]
fn workspace_members_and_product_dependency_dag_are_exact() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Value = serde_json::from_slice(&output.stdout).expect("valid metadata JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata packages must be an array");

    let expected_members = BTreeSet::from([
        "evertrace-capture",
        "evertrace-cli",
        "evertrace-codex",
        "evertrace-domain",
        "evertrace-engine",
        "evertrace-hook",
        "evertrace-protocol",
        "evertrace-store",
        "evertrace-testkit",
        "evertrace-tui",
        "evertraced",
    ]);
    let actual_members = packages
        .iter()
        .map(|package| package["name"].as_str().expect("package name"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_members, expected_members);

    let testkit = packages
        .iter()
        .find(|package| package["name"] == "evertrace-testkit")
        .expect("testkit package");
    let actual_testkit_dev_dependencies = testkit["dependencies"]
        .as_array()
        .expect("dependencies must be an array")
        .iter()
        .filter(|dependency| dependency["source"].is_null())
        .filter(|dependency| dependency["kind"] == "dev")
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_testkit_dev_dependencies,
        BTreeSet::from([
            "evertrace-capture",
            "evertrace-codex",
            "evertrace-domain",
            "evertrace-engine",
            "evertrace-protocol",
            "evertrace-store",
            "evertrace-tui",
        ])
    );

    let expected_dag = BTreeMap::from([
        ("evertrace-capture", BTreeSet::from(["evertrace-domain"])),
        (
            "evertrace-cli",
            BTreeSet::from([
                "evertrace-codex",
                "evertrace-domain",
                "evertrace-protocol",
                "evertrace-store",
                "evertrace-tui",
            ]),
        ),
        ("evertrace-codex", BTreeSet::from(["evertrace-domain"])),
        ("evertrace-domain", BTreeSet::new()),
        (
            "evertrace-engine",
            BTreeSet::from([
                "evertrace-capture",
                "evertrace-codex",
                "evertrace-domain",
                "evertrace-store",
            ]),
        ),
        (
            "evertrace-hook",
            BTreeSet::from([
                "evertrace-capture",
                "evertrace-codex",
                "evertrace-domain",
                "evertrace-protocol",
            ]),
        ),
        ("evertrace-protocol", BTreeSet::from(["evertrace-domain"])),
        (
            "evertrace-store",
            BTreeSet::from(["evertrace-capture", "evertrace-domain"]),
        ),
        ("evertrace-testkit", BTreeSet::new()),
        (
            "evertrace-tui",
            BTreeSet::from(["evertrace-domain", "evertrace-protocol"]),
        ),
        (
            "evertraced",
            BTreeSet::from(["evertrace-engine", "evertrace-protocol"]),
        ),
    ]);

    let mut actual_dag = BTreeMap::new();
    for package in packages {
        let package_name = package["name"].as_str().expect("package name");
        let normal_local_dependencies = package["dependencies"]
            .as_array()
            .expect("dependencies must be an array")
            .iter()
            .filter(|dependency| dependency["source"].is_null())
            .filter(|dependency| dependency["kind"].is_null())
            .map(|dependency| dependency["name"].as_str().expect("dependency name"))
            .collect::<BTreeSet<_>>();
        actual_dag.insert(package_name, normal_local_dependencies);
    }
    assert_eq!(actual_dag, expected_dag);

    for product in expected_members
        .iter()
        .copied()
        .filter(|name| *name != "evertrace-testkit")
    {
        let mut pending = vec![product];
        let mut closure = BTreeSet::new();
        while let Some(current) = pending.pop() {
            for dependency in &expected_dag[current] {
                if closure.insert(*dependency) {
                    pending.push(dependency);
                }
            }
        }
        assert!(!closure.contains("evertrace-testkit"));
    }
}
