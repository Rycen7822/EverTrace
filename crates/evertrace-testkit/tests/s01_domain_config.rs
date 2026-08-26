use std::str::FromStr;

use evertrace_domain::canonical::{self, CanonicalError, CanonicalValue};
use evertrace_domain::config::{
    ChangeClass, DurationValue, EffectiveConfig, RESTART_REQUIRED_FIELDS, classify_change,
};
use evertrace_domain::error::{ErrorCode, PublicError};
use evertrace_domain::ids::{
    AnyPublicId, CommandId, IdParseError, JobId, OrganizeTarget, RequestId, TaskId,
};
use evertrace_domain::revision::{
    AlgorithmRevision, ImmutableRevision, RevisionId, RevisionIdError,
};

const UUID_V7: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4a";
const UUID_V7_NEXT: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4b";
const UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";
const UUID_V7_NON_RFC: &str = "01890f47-6a4a-7cc1-18b9-01890f476a4a";
const EXAMPLE: &str = include_str!("../../../config/evertrace.example.toml");

#[test]
fn public_id_families_are_strict_and_organize_targets_are_bounded() {
    let digest = "ab".repeat(32);
    let digest_families = ["obs", "occ", "src", "wiki", "core", "cas"];
    let uuid_families = [
        "cap", "op", "se", "wb", "repo", "wt", "wts", "wtt", "int", "recreq", "rec", "recapp",
        "task", "ws", "lane", "ep", "att", "cmp", "run", "atom", "proc", "proposal", "coremem",
        "art", "dup",
    ];

    for family in digest_families {
        let parsed = format!("{family}:{digest}")
            .parse::<AnyPublicId>()
            .expect("valid deterministic ID");
        assert_eq!(parsed.family(), family);
    }
    for family in uuid_families {
        let parsed = format!("{family}:{UUID_V7}")
            .parse::<AnyPublicId>()
            .expect("valid UUIDv7 ID");
        assert_eq!(parsed.family(), family);
    }

    assert_eq!(
        TaskId::from_str(&format!("ws:{UUID_V7}")),
        Err(IdParseError::WrongFamily)
    );
    assert_eq!(
        format!("task:{UUID_V4}").parse::<AnyPublicId>(),
        Err(IdParseError::WrongUuidVersion)
    );
    assert_eq!(
        format!("task:{}", UUID_V7.to_uppercase()).parse::<AnyPublicId>(),
        Err(IdParseError::NonCanonicalUuid)
    );
    assert_eq!(
        format!("task:{UUID_V7_NON_RFC}").parse::<AnyPublicId>(),
        Err(IdParseError::WrongUuidVariant)
    );
    assert!(
        format!("obs:{}", digest.to_uppercase())
            .parse::<AnyPublicId>()
            .is_err()
    );
    assert!("obs:".parse::<AnyPublicId>().is_err());
    assert!("path_hint:anything".parse::<AnyPublicId>().is_err());
    assert!("@active".parse::<AnyPublicId>().is_err());

    assert!(format!("atom:{UUID_V7}").parse::<OrganizeTarget>().is_ok());
    assert!(format!("proc:{UUID_V7}").parse::<OrganizeTarget>().is_ok());
    assert!(
        format!("coremem:{UUID_V7}")
            .parse::<OrganizeTarget>()
            .is_ok()
    );
    assert_eq!(
        format!("wiki:{digest}").parse::<OrganizeTarget>(),
        Err(IdParseError::ProjectionNotOrganizable)
    );
    assert_eq!(
        format!("core:{digest}").parse::<OrganizeTarget>(),
        Err(IdParseError::ProjectionNotOrganizable)
    );

    for internal in [
        CommandId::from_str(UUID_V7).map(|id| id.to_string()),
        JobId::from_str(UUID_V7).map(|id| id.to_string()),
        RequestId::from_str(UUID_V7).map(|id| id.to_string()),
    ] {
        assert_eq!(internal.expect("valid internal UUIDv7"), UUID_V7);
    }
    assert_eq!(
        CommandId::from_str(&format!("cmd:{UUID_V7}")),
        Err(IdParseError::InvalidUuid)
    );
    assert_eq!(
        JobId::from_str(UUID_V4),
        Err(IdParseError::WrongUuidVersion)
    );
    assert_eq!(
        RequestId::from_str(&UUID_V7.to_uppercase()),
        Err(IdParseError::NonCanonicalUuid)
    );
    assert_eq!(
        CommandId::from_str(UUID_V7_NON_RFC),
        Err(IdParseError::WrongUuidVariant)
    );
    let serialized = serde_json::to_string(&CommandId::from_str(UUID_V7).expect("command ID"))
        .expect("serialize command ID");
    assert_eq!(serialized, format!("\"{UUID_V7}\""));
    assert_eq!(
        serde_json::from_str::<CommandId>(&serialized).expect("deserialize command ID"),
        CommandId::from_str(UUID_V7).expect("command ID")
    );
}

#[test]
fn canonical_encoding_has_stable_tags_order_lengths_and_keyed_digest() {
    let mut null_golden = b"ETC1".to_vec();
    null_golden.extend_from_slice(&1_u64.to_be_bytes());
    null_golden.push(b's');
    null_golden.extend_from_slice(&1_u32.to_be_bytes());
    null_golden.push(b'N');
    assert_eq!(
        canonical::encode("s", 1, &CanonicalValue::Null).expect("canonical null"),
        null_golden
    );
    let known_encoded = hex_bytes("45544331000000000000000173000000014e");
    assert_eq!(
        canonical::encode("s", 1, &CanonicalValue::Null).expect("known encoding"),
        known_encoded
    );
    let known_sha = hex_bytes("11d9942122bf6ef8b179f5b55a2a9bbf73e416a9126dbc5a0a3d26c5bb7ab20e");
    assert_eq!(
        canonical::sha256("s", 1, &CanonicalValue::Null)
            .expect("known SHA-256")
            .as_slice(),
        known_sha.as_slice()
    );
    let known_hmac = hex_bytes("b7f471fb880105834422de39eea760ba576440ff50d559f5fc2dd89097492aca");
    assert_eq!(
        canonical::hmac_sha256(b"key", "s", 1, &CanonicalValue::Null)
            .expect("known HMAC-SHA-256")
            .as_slice(),
        known_hmac.as_slice()
    );

    let entries = vec![
        ("é".to_owned(), CanonicalValue::String("雪".to_owned())),
        ("a".to_owned(), CanonicalValue::Integer(-7)),
        ("n".to_owned(), CanonicalValue::Null),
        ("b".to_owned(), CanonicalValue::Bool(true)),
        ("raw".to_owned(), CanonicalValue::Bytes(vec![0, 255])),
        (
            "seq".to_owned(),
            CanonicalValue::Sequence(vec![CanonicalValue::Integer(1)]),
        ),
    ];
    let mut reversed = entries.clone();
    reversed.reverse();
    let encoded =
        canonical::encode("identity", 1, &CanonicalValue::Map(entries)).expect("canonical map");
    assert_eq!(
        encoded,
        canonical::encode("identity", 1, &CanonicalValue::Map(reversed))
            .expect("canonical reversed map")
    );
    assert_ne!(
        encoded,
        canonical::encode("identity", 2, &CanonicalValue::Null).expect("versioned value")
    );
    assert_ne!(
        canonical::sha256("identity", 1, &CanonicalValue::Null).expect("digest"),
        canonical::sha256("other", 1, &CanonicalValue::Null).expect("tagged digest")
    );
    assert_ne!(
        canonical::hmac_sha256(b"key-a", "identity", 1, &CanonicalValue::Null)
            .expect("keyed digest"),
        canonical::hmac_sha256(b"key-b", "identity", 1, &CanonicalValue::Null)
            .expect("other keyed digest")
    );

    let boundary = canonical::encode("length", 1, &CanonicalValue::String("x".repeat(256)))
        .expect("length boundary");
    let length_offset = 4 + 8 + "length".len() + 4 + 1;
    assert_eq!(
        &boundary[length_offset..length_offset + 8],
        &256_u64.to_be_bytes()
    );
    assert_eq!(
        canonical::encode(
            "map",
            1,
            &CanonicalValue::Map(vec![
                ("same".to_owned(), CanonicalValue::Null),
                ("same".to_owned(), CanonicalValue::Bool(false)),
            ]),
        ),
        Err(CanonicalError::DuplicateMapKey)
    );
}

#[test]
fn immutable_revision_successor_preserves_history_and_lineage() {
    assert_eq!(
        RevisionId::from_str(UUID_V7_NON_RFC),
        Err(RevisionIdError::WrongUuidVariant)
    );
    let root_id = RevisionId::from_str(UUID_V7).expect("root revision ID");
    let successor_id = RevisionId::from_str(UUID_V7_NEXT).expect("successor revision ID");
    let root = ImmutableRevision::root(root_id, "old", 100, 7);
    let successor = root.successor(successor_id, "new", 200, 9, []);

    assert_eq!(root.payload(), &"old");
    assert_eq!(root.parent(), None);
    assert!(root.supersedes().is_empty());
    assert_eq!(root.metadata().created_at_us(), 100);
    assert_eq!(successor.payload(), &"new");
    assert_eq!(successor.parent(), Some(root_id));
    assert_eq!(successor.supersedes(), &[root_id]);
    assert_eq!(successor.metadata().created_at_us(), 200);
    assert_eq!(successor.metadata().source_watermark(), 9);
    assert_eq!(AlgorithmRevision::V1.version(), 1);
}

#[test]
fn example_round_trips_to_the_default_and_hash_tracks_semantics() {
    let example = EffectiveConfig::parse_toml(EXAMPLE).expect("valid example config");
    assert_eq!(example, EffectiveConfig::default());
    assert!(EffectiveConfig::parse_toml("").is_err());
    assert!(EffectiveConfig::parse_toml("[runtime]\nbackground_workers = 4\n").is_err());
    assert!(EffectiveConfig::parse_toml("config_version = 2\n").is_err());
    assert_eq!(
        EffectiveConfig::parse_toml("config_version = 1\n").expect("minimal config"),
        EffectiveConfig::default()
    );
    assert_eq!(
        EffectiveConfig::parse_toml("config_version = 1\n[runtime]\nbackground_workers = 4\n")
            .expect("partial runtime config"),
        parsed_with("background_workers = 2", "background_workers = 4")
            .expect("full equivalent config")
    );
    assert_eq!(
        EffectiveConfig::parse_toml("config_version = 1\n[search]\nsearch_token_budget = 0\n")
            .expect("partial search config"),
        parsed_with("search_token_budget = 600", "search_token_budget = 0")
            .expect("full equivalent search config")
    );
    let serialized = example.to_toml().expect("serialize effective config");
    assert_eq!(
        EffectiveConfig::parse_toml(&serialized).expect("semantic round trip"),
        example
    );
    assert_eq!(
        EffectiveConfig::parse_toml(EXAMPLE)
            .expect("repeat parse")
            .hash(),
        example.hash()
    );
    let changed = parsed_with("search_token_budget = 600", "search_token_budget = 601")
        .expect("valid semantic change");
    assert_ne!(changed.hash(), example.hash());
}

#[test]
fn config_numeric_and_duration_boundaries_are_strict() {
    let cases = [
        ("background_workers = 2", "background_workers = 1", true),
        ("background_workers = 2", "background_workers = 8", true),
        ("background_workers = 2", "background_workers = 0", false),
        ("background_workers = 2", "background_workers = 9", false),
        ("idle_after = \"30m\"", "idle_after = \"5m\"", true),
        ("idle_after = \"30m\"", "idle_after = \"24h\"", true),
        ("idle_after = \"30m\"", "idle_after = \"299s\"", false),
        ("idle_after = \"30m\"", "idle_after = \"25h\"", false),
        (
            "integrity_sweep_interval = \"24h\"",
            "integrity_sweep_interval = \"1h\"",
            true,
        ),
        (
            "integrity_sweep_interval = \"24h\"",
            "integrity_sweep_interval = \"7d\"",
            true,
        ),
        (
            "integrity_sweep_interval = \"24h\"",
            "integrity_sweep_interval = \"59m\"",
            false,
        ),
        (
            "integrity_sweep_interval = \"24h\"",
            "integrity_sweep_interval = \"8d\"",
            false,
        ),
        (
            "max_llm_tasks_per_run = 4",
            "max_llm_tasks_per_run = 0",
            true,
        ),
        (
            "max_llm_tasks_per_run = 4",
            "max_llm_tasks_per_run = 16",
            true,
        ),
        (
            "max_llm_tasks_per_run = 4",
            "max_llm_tasks_per_run = 17",
            false,
        ),
        ("max_wall_time = \"10m\"", "max_wall_time = \"1m\"", true),
        ("max_wall_time = \"10m\"", "max_wall_time = \"24h\"", true),
        ("max_wall_time = \"10m\"", "max_wall_time = \"59s\"", false),
        ("max_wall_time = \"10m\"", "max_wall_time = \"25h\"", false),
        (
            "stable_min_outcome_supported = 3",
            "stable_min_outcome_supported = 2",
            false,
        ),
        ("search_token_budget = 600", "search_token_budget = 1", true),
        (
            "search_token_budget = 600",
            "search_token_budget = 1200",
            true,
        ),
        ("search_token_budget = 600", "search_token_budget = 0", true),
        (
            "search_token_budget = 600",
            "search_token_budget = 1201",
            false,
        ),
        ("get_token_budget = 1200", "get_token_budget = 1", true),
        ("get_token_budget = 1200", "get_token_budget = 2400", true),
        ("get_token_budget = 1200", "get_token_budget = 0", true),
        ("get_token_budget = 1200", "get_token_budget = 2401", false),
        (
            "max_concurrent_body_imports = 1",
            "max_concurrent_body_imports = 4",
            true,
        ),
        (
            "max_concurrent_body_imports = 1",
            "max_concurrent_body_imports = 0",
            false,
        ),
        (
            "max_concurrent_body_imports = 1",
            "max_concurrent_body_imports = 5",
            false,
        ),
        (
            "max_body_import_mib_per_run = 256",
            "max_body_import_mib_per_run = 16",
            true,
        ),
        (
            "max_body_import_mib_per_run = 256",
            "max_body_import_mib_per_run = 2048",
            true,
        ),
        (
            "max_body_import_mib_per_run = 256",
            "max_body_import_mib_per_run = 15",
            false,
        ),
        (
            "max_body_import_mib_per_run = 256",
            "max_body_import_mib_per_run = 2049",
            false,
        ),
        ("preview_bytes = 8192", "preview_bytes = 256", true),
        ("preview_bytes = 8192", "preview_bytes = 65536", false),
        ("preview_bytes = 8192", "preview_bytes = 255", false),
        ("preview_bytes = 8192", "preview_bytes = 65537", false),
        (
            "inline_payload_bytes = 32768",
            "inline_payload_bytes = 1024",
            false,
        ),
        (
            "inline_payload_bytes = 32768",
            "inline_payload_bytes = 1048576",
            true,
        ),
        (
            "inline_payload_bytes = 32768",
            "inline_payload_bytes = 1023",
            false,
        ),
        (
            "inline_payload_bytes = 32768",
            "inline_payload_bytes = 1048577",
            false,
        ),
        (
            "capture_timeout = \"10s\"",
            "capture_timeout = \"1s\"",
            true,
        ),
        (
            "capture_timeout = \"10s\"",
            "capture_timeout = \"2m\"",
            true,
        ),
        (
            "capture_timeout = \"10s\"",
            "capture_timeout = \"121s\"",
            false,
        ),
        ("max_bundle_mib = 256", "max_bundle_mib = 16", false),
        ("max_bundle_mib = 256", "max_bundle_mib = 4096", true),
        ("max_bundle_mib = 256", "max_bundle_mib = 15", false),
        ("max_bundle_mib = 256", "max_bundle_mib = 4097", false),
        (
            "max_untracked_file_mib = 16",
            "max_untracked_file_mib = 1",
            true,
        ),
        (
            "max_untracked_file_mib = 16",
            "max_untracked_file_mib = 1024",
            true,
        ),
        (
            "max_untracked_file_mib = 16",
            "max_untracked_file_mib = 0",
            false,
        ),
        (
            "max_untracked_file_mib = 16",
            "max_untracked_file_mib = 1025",
            false,
        ),
        (
            "max_untracked_total_mib = 128",
            "max_untracked_total_mib = 1",
            true,
        ),
        (
            "max_untracked_total_mib = 128",
            "max_untracked_total_mib = 4096",
            false,
        ),
        (
            "max_untracked_total_mib = 128",
            "max_untracked_total_mib = 0",
            false,
        ),
        (
            "max_untracked_total_mib = 128",
            "max_untracked_total_mib = 4097",
            false,
        ),
        ("timeout = \"90s\"", "timeout = \"1s\"", true),
        ("timeout = \"90s\"", "timeout = \"10m\"", true),
        ("timeout = \"90s\"", "timeout = \"601s\"", false),
        ("max_concurrency = 1", "max_concurrency = 8", true),
        ("max_concurrency = 1", "max_concurrency = 0", false),
        ("max_concurrency = 1", "max_concurrency = 9", false),
        (
            "max_episode_enrichments = 2",
            "max_episode_enrichments = 1",
            true,
        ),
        (
            "max_episode_enrichments = 2",
            "max_episode_enrichments = 4",
            true,
        ),
        (
            "max_episode_enrichments = 2",
            "max_episode_enrichments = 0",
            false,
        ),
        (
            "max_episode_enrichments = 2",
            "max_episode_enrichments = 5",
            false,
        ),
        (
            "daily_input_token_budget = 500000",
            "daily_input_token_budget = 1",
            true,
        ),
        (
            "daily_input_token_budget = 500000",
            "daily_input_token_budget = 0",
            false,
        ),
        (
            "daily_output_token_budget = 100000",
            "daily_output_token_budget = 1",
            true,
        ),
        (
            "daily_output_token_budget = 100000",
            "daily_output_token_budget = 0",
            false,
        ),
        ("daily_call_budget = 200", "daily_call_budget = 1", true),
        ("daily_call_budget = 200", "daily_call_budget = 0", false),
        (
            "daily_wall_time_budget = \"2h\"",
            "daily_wall_time_budget = \"1m\"",
            true,
        ),
        (
            "daily_wall_time_budget = \"2h\"",
            "daily_wall_time_budget = \"24h\"",
            true,
        ),
        (
            "daily_wall_time_budget = \"2h\"",
            "daily_wall_time_budget = \"59s\"",
            false,
        ),
        (
            "daily_wall_time_budget = \"2h\"",
            "daily_wall_time_budget = \"25h\"",
            false,
        ),
    ];
    for (from, to, valid) in cases {
        assert_eq!(parsed_with(from, to).is_ok(), valid, "replacement: {to}");
    }

    assert!(
        parsed_with(
            "inline_payload_bytes = 32768",
            "inline_payload_bytes = 8191"
        )
        .is_err()
    );
    assert!(
        parsed_with(
            "max_untracked_total_mib = 128",
            "max_untracked_total_mib = 257"
        )
        .is_err()
    );
    assert!(
        parsed_with(
            "max_untracked_file_mib = 16",
            "max_untracked_file_mib = 129"
        )
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            ("preview_bytes = 8192", "preview_bytes = 256"),
            (
                "inline_payload_bytes = 32768",
                "inline_payload_bytes = 1024"
            ),
        ])
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            ("preview_bytes = 8192", "preview_bytes = 65536"),
            (
                "inline_payload_bytes = 32768",
                "inline_payload_bytes = 65536"
            ),
        ])
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            ("max_bundle_mib = 256", "max_bundle_mib = 16"),
            (
                "max_untracked_total_mib = 128",
                "max_untracked_total_mib = 16"
            ),
        ])
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            ("max_bundle_mib = 256", "max_bundle_mib = 1024"),
            (
                "max_untracked_file_mib = 16",
                "max_untracked_file_mib = 1024"
            ),
            (
                "max_untracked_total_mib = 128",
                "max_untracked_total_mib = 1024"
            ),
        ])
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            ("max_untracked_file_mib = 16", "max_untracked_file_mib = 1"),
            (
                "max_untracked_total_mib = 128",
                "max_untracked_total_mib = 1"
            ),
        ])
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            ("max_bundle_mib = 256", "max_bundle_mib = 4096"),
            (
                "max_untracked_total_mib = 128",
                "max_untracked_total_mib = 4096"
            ),
        ])
        .is_ok()
    );

    for invalid in [
        "",
        "-1s",
        "1.5s",
        "1h30m",
        "10",
        "1w",
        "18446744073709551615d",
    ] {
        assert!(
            DurationValue::from_str(invalid).is_err(),
            "duration: {invalid}"
        );
    }
}

#[test]
fn config_unknown_fields_paths_urls_names_and_restart_classification_are_strict() {
    assert!(parsed_with("config_version = 1", "config_version = 1\nunknown = true").is_err());
    assert!(
        parsed_with(
            "background_workers = 2",
            "background_workers = 2\nunknown = true"
        )
        .is_err()
    );
    assert!(
        parsed_with(
            "data_dir = \"~/.local/share/evertrace\"",
            "data_dir = \"relative/path\""
        )
        .is_err()
    );
    assert!(
        parsed_with(
            "data_dir = \"~/.local/share/evertrace\"",
            "data_dir = \"\\u0000\""
        )
        .is_err()
    );
    for data_dir in [
        "$HOME",
        "$HOME/evertrace",
        "$A_0/data",
        "${XDG_DATA_HOME}",
        "${XDG_DATA_HOME}/evertrace",
    ] {
        assert!(
            parsed_with("~/.local/share/evertrace", data_dir).is_ok(),
            "data_dir: {data_dir}"
        );
    }
    for data_dir in [
        "$",
        "${}",
        "$0BAD",
        "$BAD-NAME/path",
        "${NAME",
        "${BAD-NAME}",
        "${NAME}suffix",
        "~user",
        "relative/path",
    ] {
        assert!(
            parsed_with("~/.local/share/evertrace", data_dir).is_err(),
            "data_dir: {data_dir}"
        );
    }
    assert!(parsed_with("log_level = \"info\"", "log_level = \"verbose\"").is_err());
    assert!(parsed_with("atom = \"semi_auto\"", "atom = \"automatic\"").is_err());
    assert!(
        parsed_with(
            "episode_enrichment = \"adaptive\"",
            "episode_enrichment = \"always\""
        )
        .is_err()
    );

    for url in [
        "https://example.com/v1",
        "http://localhost:8080/v1",
        "http://127.0.0.1/v1",
        "http://[::1]/v1",
    ] {
        assert!(
            parsed_with("https://provider.example/v1", url).is_ok(),
            "URL: {url}"
        );
    }
    for url in [
        "http://example.com/v1",
        "ftp://example.com/v1",
        "/relative",
        "https://user@example.com/v1",
        "https://@example.com/v1",
        "https://example.com/v1#fragment",
        "https://",
    ] {
        assert!(
            parsed_with("https://provider.example/v1", url).is_err(),
            "URL: {url}"
        );
    }

    for env_name in ["A", "_A", "A0_B"] {
        assert!(parsed_with("EVERTRACE_LLM_API_KEY", env_name).is_ok());
    }
    for env_name in ["", "0A", "A-B", "A B"] {
        assert!(parsed_with("EVERTRACE_LLM_API_KEY", env_name).is_err());
    }
    assert!(parsed_with("EVERTRACE_LLM_API_KEY", &"A".repeat(128)).is_ok());
    assert!(parsed_with("EVERTRACE_LLM_API_KEY", &"A".repeat(129)).is_err());

    assert!(parsed_with("openai_compatible", "x").is_ok());
    assert!(parsed_with("openai_compatible", &"x".repeat(256)).is_ok());
    assert!(parsed_with("openai_compatible", &"x".repeat(257)).is_err());
    assert!(parsed_with("provider-model-name", "").is_err());
    assert!(parsed_with("provider-model-name", &"m".repeat(256)).is_ok());
    assert!(parsed_with("provider-model-name", &"m".repeat(257)).is_err());
    assert!(
        parsed_with(
            "unlimited_token_budget = false",
            "unlimited_token_budget = true"
        )
        .is_ok()
    );
    assert!(
        parsed_with_many(&[
            (
                "daily_input_token_budget = 500000",
                "daily_input_token_budget = 0"
            ),
            (
                "unlimited_token_budget = false",
                "unlimited_token_budget = true"
            ),
        ])
        .is_err()
    );

    assert_eq!(
        RESTART_REQUIRED_FIELDS,
        ["runtime.data_dir", "runtime.background_workers"]
    );
    assert_eq!(
        classify_change("runtime.data_dir"),
        Some(ChangeClass::RestartRequired)
    );
    assert_eq!(
        classify_change("runtime.background_workers"),
        Some(ChangeClass::RestartRequired)
    );
    assert_eq!(
        classify_change("llm.provider"),
        Some(ChangeClass::HotReload)
    );
    assert_eq!(classify_change("unknown"), None);

    let example_value = toml::from_str::<toml::Value>(EXAMPLE).expect("example TOML value");
    let mut leaf_paths = Vec::new();
    collect_leaf_paths("", &example_value, &mut leaf_paths);
    leaf_paths.retain(|path| path != "config_version");
    let mut restart_fields = Vec::new();
    for path in &leaf_paths {
        match classify_change(path).expect("every stable leaf field is classified") {
            ChangeClass::RestartRequired => restart_fields.push(path.as_str()),
            ChangeClass::HotReload => {}
        }
    }
    restart_fields.sort_unstable();
    assert_eq!(
        restart_fields,
        ["runtime.background_workers", "runtime.data_dir"]
    );
}

#[test]
fn stable_error_codes_and_public_format_are_payload_free() {
    let expected = [
        "invalid_input",
        "scope_unresolved",
        "conflict",
        "not_found",
        "untrusted",
        "degraded_index",
        "pending_import",
        "resource_exhausted",
        "protocol_mismatch",
        "maintenance_mode",
        "idempotency_conflict",
        "store_corrupt",
        "internal",
    ];
    let actual = ErrorCode::ALL.map(ErrorCode::as_str);
    assert_eq!(actual, expected);
    for code in ErrorCode::ALL {
        let public = PublicError::new(code).to_string();
        assert_eq!(public, code.as_str());
        assert!(!public.contains("SECRET_PAYLOAD"));
    }
}

fn parsed_with(
    from: &str,
    to: &str,
) -> Result<EffectiveConfig, evertrace_domain::config::ConfigError> {
    let quoted_from = format!("\"{from}\"");
    let quoted_to = format!("\"{to}\"");
    let (needle, replacement) = if EXAMPLE.contains(&quoted_from) {
        (quoted_from.as_str(), quoted_to.as_str())
    } else {
        (from, to)
    };
    assert!(
        EXAMPLE.contains(needle),
        "missing replacement source: {from}"
    );
    EffectiveConfig::parse_toml(&EXAMPLE.replacen(needle, replacement, 1))
}

fn parsed_with_many(
    replacements: &[(&str, &str)],
) -> Result<EffectiveConfig, evertrace_domain::config::ConfigError> {
    let mut config = EXAMPLE.to_owned();
    for (from, to) in replacements {
        assert!(config.contains(from), "missing replacement source: {from}");
        config = config.replacen(from, to, 1);
    }
    EffectiveConfig::parse_toml(&config)
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn collect_leaf_paths(prefix: &str, value: &toml::Value, output: &mut Vec<String>) {
    if let toml::Value::Table(table) = value {
        for (key, child) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            collect_leaf_paths(&path, child, output);
        }
    } else {
        output.push(prefix.to_owned());
    }
}
