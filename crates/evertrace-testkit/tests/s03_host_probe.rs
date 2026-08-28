use std::{collections::BTreeSet, fs, path::PathBuf};

use evertrace_codex::{
    HostProbeReport,
    adapter_manifest::{
        AdapterCapabilityManifest, CaptureGuarantee, ManifestError, ObservableCapability,
        SubagentTrace,
    },
    capability::{
        CanaryStatus, HookActivation, HookDiagnostic, McpBindingEvidence, McpBindingMechanism,
        McpIdentityStrength, McpSessionBinding, evaluate_hook,
    },
    hook_input::HookActivationEvidence,
    policy::PolicyCandidateOrigin,
    probe::{
        EvidenceSourceKind, GateReason, GateResult, NormalizationCanaryEvidence, ProbeContext,
        ProbeEvidence,
    },
};
use evertrace_domain::config::{ConfigFile, EffectiveConfig};
use evertrace_engine::RecoveryRuntimeSettings;
use serde_json::Value;

#[path = "../src/probe.rs"]
mod probe_fixture;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn report(evidence: &ProbeEvidence) -> HostProbeReport {
    let mut evidence = evidence.clone();
    qualify_normalization_canary(&mut evidence);
    let mut context = synthetic_context();
    context.evidence_source = EvidenceSourceKind::ObservedHostCanary;
    HostProbeReport::evaluate(&context, &evidence).unwrap()
}

fn synthetic_context() -> ProbeContext {
    probe_fixture::fixture_context("complete")
}

fn qualify_normalization_canary(evidence: &mut ProbeEvidence) {
    let Some(normalization) = evidence.normalization.as_mut() else {
        return;
    };
    for observation in &mut normalization.observations {
        observation.occurrence_schema_version = 1;
        observation.host_instance_id = "host-a".into();
    }
    normalization.canaries = NormalizationCanaryEvidence {
        fork_isolated: true,
        resume_isolated: true,
        retry_ordinal_isolated: true,
        replay_deduplicated: true,
        nonidentity_similarity_not_merged: true,
        missing_field_rejected: true,
        field_conflict_rejected: true,
    };
}

fn gate_results(report: &HostProbeReport) -> [GateResult; 5] {
    [
        report.capture().result(),
        report.recovery().result(),
        report.active_search_due().result(),
        report.strong_normalization().result(),
        report.project_policy().result(),
    ]
}

fn hook_evidence() -> HookActivationEvidence {
    HookActivationEvidence {
        wiring_detected: true,
        trusted: true,
        enabled: true,
        expected_hash: Some(DIGEST.into()),
        observed_hash: Some(DIGEST.into()),
        canary: CanaryStatus::Passed,
        evidence_refs: vec!["hook:1".into()],
        protected_digest: Some(DIGEST.into()),
    }
}

#[test]
fn manifest_is_closed_round_trippable_and_relation_checked() {
    let manifest = report(&probe_fixture::fixture("complete"))
        .manifest()
        .clone();
    let encoded = manifest.to_json().unwrap();
    assert_eq!(
        AdapterCapabilityManifest::from_json(&encoded).unwrap(),
        manifest
    );

    let mut json: Value = serde_json::from_str(&encoded).unwrap();
    json["unknown"] = Value::Bool(true);
    assert_eq!(
        AdapterCapabilityManifest::from_json(&json.to_string()),
        Err(ManifestError::InvalidJson)
    );

    let mut json: Value = serde_json::from_str(&encoded).unwrap();
    json["adapter_kind"] = Value::String("unknown_adapter".into());
    assert_eq!(
        AdapterCapabilityManifest::from_json(&json.to_string()),
        Err(ManifestError::InvalidJson)
    );

    let mut invalid = manifest.clone();
    invalid.required_for_full.pop();
    assert_eq!(
        invalid.validate(),
        Err(ManifestError::InvalidCapabilityRelationship)
    );
    let mut invalid = manifest.clone();
    invalid
        .observable
        .push(ObservableCapability::RawHiddenReasoning);
    assert_eq!(
        invalid.validate(),
        Err(ManifestError::InvalidCapabilityRelationship)
    );
    let mut invalid = manifest.clone();
    invalid.mcp_session_binding = McpSessionBinding::CwdOnly;
    assert_eq!(invalid.validate(), Err(ManifestError::InvalidMcpBinding));
    let object = serde_json::from_str::<Value>(&encoded).unwrap();
    assert!(object.get("supported").is_none());

    let mut mismatched = manifest.clone();
    mismatched.host_version_range.push_str("-changed");
    assert_eq!(mismatched.validate(), Err(ManifestError::InvalidManifestId));
    assert_eq!(
        AdapterCapabilityManifest::from_json(&serde_json::to_string(&mismatched).unwrap()),
        Err(ManifestError::InvalidManifestId)
    );
}

#[test]
fn manifest_revision_is_content_bound_and_distinct_from_adapter_version() {
    let evidence = probe_fixture::fixture("complete");
    let original = report(&evidence);
    let repeated = report(&evidence);
    assert_eq!(
        original.manifest().adapter_manifest_id,
        repeated.manifest().adapter_manifest_id
    );
    assert_ne!(
        original.manifest().adapter_manifest_id,
        original.manifest().adapter_version
    );

    let mut changed_context = synthetic_context();
    changed_context
        .observed_host_version_range
        .push_str("-changed");
    let changed = HostProbeReport::evaluate(&changed_context, &evidence).unwrap();
    assert_ne!(
        original.manifest().adapter_manifest_id,
        changed.manifest().adapter_manifest_id
    );

    let mut changed_evidence = evidence;
    changed_evidence.capture.as_mut().unwrap().observed = vec![ObservableCapability::ChildToolCall];
    let changed = report(&changed_evidence);
    assert_ne!(
        original.manifest().adapter_manifest_id,
        changed.manifest().adapter_manifest_id
    );
}

#[test]
fn empty_environment_disables_all_gates_honestly() {
    let evidence = probe_fixture::fixture("empty");
    let report = HostProbeReport::evaluate(&ProbeContext::unobserved_codex(), &evidence).unwrap();
    assert_eq!(gate_results(&report), [GateResult::Disabled; 5]);
    assert_eq!(report.hook().activation, HookActivation::Missing);
    assert_eq!(report.hook().diagnostic, None);
    assert_eq!(report.mcp().binding, McpSessionBinding::Unavailable);
    assert_eq!(
        report.manifest().capture_guarantee,
        CaptureGuarantee::Opaque
    );
    assert_eq!(report.manifest().subagent_trace, SubagentTrace::Unavailable);
    assert!(report.manifest().observable.is_empty());
    assert!(report.manifest().project_policy_surfaces.is_empty());
    assert_eq!(
        report.manifest().required_for_full,
        evertrace_codex::source_catalog::REQUIRED_FOR_FULL
    );
    for receipt in [
        report.capture(),
        report.recovery(),
        report.active_search_due(),
        report.strong_normalization(),
        report.project_policy(),
    ] {
        assert_eq!(receipt.reason(), GateReason::MissingEvidence);
        assert_eq!(receipt.protected_digest().len(), 64);
    }
}

#[test]
fn complete_evidence_enables_five_independent_gates_and_is_stable() {
    let evidence = probe_fixture::fixture("complete");
    let first = report(&evidence);
    let second = report(&evidence);
    assert_eq!(gate_results(&first), [GateResult::Enabled; 5]);
    assert_eq!(first, second);
    assert_eq!(first.hook().activation, HookActivation::Active);
    assert_eq!(first.mcp().binding, McpSessionBinding::Exact);
    assert_eq!(first.mcp().mechanism, McpBindingMechanism::HookStamped);
    assert_eq!(first.manifest().capture_guarantee, CaptureGuarantee::Full);
    let config = EffectiveConfig::new(ConfigFile::default()).unwrap();
    let runtime = RecoveryRuntimeSettings::compile(&config, Some(&first), 7).unwrap();
    assert_eq!(runtime.gate, evertrace_capture::RecoveryGateMode::Active);
    assert_eq!(
        runtime.adapter_manifest_id.as_deref(),
        Some(first.manifest().adapter_manifest_id.as_str())
    );
    assert_eq!(runtime.effective_config_hash, config.hash());
}

#[test]
fn synthetic_fixture_alone_does_not_activate_strong_normalization() {
    let evidence = probe_fixture::fixture("complete");
    let report = HostProbeReport::evaluate(&synthetic_context(), &evidence).unwrap();
    assert_eq!(report.strong_normalization().result(), GateResult::Disabled);
    assert_eq!(
        report.strong_normalization().reason(),
        GateReason::EvidenceIntegrityFailed
    );
    assert_eq!(report.recovery().result(), GateResult::Disabled);
    assert_eq!(report.recovery().reason(), GateReason::RecoveryCanaryFailed);
    let config = EffectiveConfig::new(ConfigFile::default()).unwrap();
    let runtime = RecoveryRuntimeSettings::compile(&config, Some(&report), 7).unwrap();
    assert_eq!(runtime.gate, evertrace_capture::RecoveryGateMode::Disabled);
}

#[test]
fn probe_compiles_degraded_manifests_and_does_not_accept_a_caller_manifest() {
    let complete = probe_fixture::fixture("complete");
    let claimed_full = report(&complete).manifest().clone();
    assert_eq!(claimed_full.capture_guarantee, CaptureGuarantee::Full);

    let empty =
        HostProbeReport::evaluate(&ProbeContext::unobserved_codex(), &ProbeEvidence::empty())
            .unwrap();
    assert_eq!(empty.manifest().capture_guarantee, CaptureGuarantee::Opaque);
    assert_ne!(empty.manifest(), &claimed_full);

    let mut partial_evidence = complete.clone();
    partial_evidence.capture.as_mut().unwrap().observed = vec![ObservableCapability::ChildToolCall];
    let partial = report(&partial_evidence);
    assert_eq!(
        partial.manifest().capture_guarantee,
        CaptureGuarantee::Partial
    );
    assert!(partial.manifest().validate().is_ok());

    let mut opaque_evidence = complete;
    opaque_evidence.capture.as_mut().unwrap().observed = vec![
        ObservableCapability::DelegationStart,
        ObservableCapability::ChildFinalResult,
        ObservableCapability::DelegationEnd,
    ];
    let opaque = report(&opaque_evidence);
    assert_eq!(
        opaque.manifest().capture_guarantee,
        CaptureGuarantee::Opaque
    );
    assert!(opaque.manifest().validate().is_ok());
}

#[test]
fn official_hook_fields_do_not_overstate_child_trace() {
    let mut evidence = probe_fixture::fixture("complete");
    evidence.capture.as_mut().unwrap().observed = vec![
        ObservableCapability::DelegationStart,
        ObservableCapability::ChildSessionId,
        ObservableCapability::ChildFinalResult,
        ObservableCapability::DelegationEnd,
    ];
    let mut context = synthetic_context();
    context.evidence_source = EvidenceSourceKind::OfficialCodexHookContract;
    context.observed_host_version_range = "official-public-hook-contract".into();
    let report = HostProbeReport::evaluate(&context, &evidence).unwrap();
    assert_eq!(
        report.manifest().capture_guarantee,
        CaptureGuarantee::Opaque
    );
    assert_eq!(
        report.manifest().subagent_trace,
        SubagentTrace::ParentSummaryOnly
    );
    assert_eq!(report.capture().result(), GateResult::Disabled);
}

#[test]
fn breaking_each_gate_only_disables_that_gate() {
    let complete = probe_fixture::fixture("complete");
    let mut cases = Vec::new();

    let mut evidence = complete.clone();
    evidence.capture.as_mut().unwrap().gap_count = 1;
    cases.push((evidence, 0, GateReason::GapOrOutage));

    let mut evidence = complete.clone();
    evidence.recovery.as_mut().unwrap().pairs[0].post_sequence = None;
    cases.push((evidence, 1, GateReason::RecoveryNotFenced));

    let mut evidence = complete.clone();
    evidence.cue.as_mut().unwrap().sessions_isolated = false;
    cases.push((evidence, 2, GateReason::SessionBindingUnproven));

    let mut evidence = complete.clone();
    evidence
        .normalization
        .as_mut()
        .unwrap()
        .fork_resume_retry_unique = false;
    cases.push((evidence, 3, GateReason::IdentityUnstable));

    let mut evidence = complete;
    evidence.policy.as_mut().unwrap().readback_matches = false;
    cases.push((evidence, 4, GateReason::PolicyReadbackMismatch));

    for (evidence, disabled_index, reason) in cases {
        let report = report(&evidence);
        let results = gate_results(&report);
        for (index, result) in results.into_iter().enumerate() {
            assert_eq!(
                result,
                if index == disabled_index {
                    GateResult::Disabled
                } else {
                    GateResult::Enabled
                }
            );
        }
        let receipts = [
            report.capture(),
            report.recovery(),
            report.active_search_due(),
            report.strong_normalization(),
            report.project_policy(),
        ];
        assert_eq!(receipts[disabled_index].reason(), reason);
    }
}

#[test]
fn hook_activation_states_and_wired_diagnostic_are_distinct() {
    let mut evidence = hook_evidence();
    assert_eq!(
        evaluate_hook(Some(&evidence)).activation,
        HookActivation::Active
    );

    evidence.wiring_detected = false;
    assert_eq!(
        evaluate_hook(Some(&evidence)).activation,
        HookActivation::Missing
    );
    evidence = hook_evidence();
    evidence.trusted = false;
    assert_eq!(
        evaluate_hook(Some(&evidence)).activation,
        HookActivation::PendingTrust
    );
    evidence = hook_evidence();
    evidence.enabled = false;
    assert_eq!(
        evaluate_hook(Some(&evidence)).activation,
        HookActivation::Disabled
    );
    evidence = hook_evidence();
    evidence.observed_hash = Some("b".repeat(64));
    assert_eq!(
        evaluate_hook(Some(&evidence)).activation,
        HookActivation::HashChanged
    );
    evidence = hook_evidence();
    evidence.canary = CanaryStatus::Failed;
    assert_eq!(
        evaluate_hook(Some(&evidence)).activation,
        HookActivation::CanaryFailed
    );
    evidence = hook_evidence();
    evidence.canary = CanaryStatus::NotRun;
    let result = evaluate_hook(Some(&evidence));
    assert_eq!(result.activation, HookActivation::Missing);
    assert_eq!(result.diagnostic, Some(HookDiagnostic::WiredUnobserved));
    assert_ne!(result.activation, HookActivation::Active);
}

#[test]
fn mcp_identity_ladder_is_fail_closed_for_tamper_replay_and_restart() {
    let direct = McpBindingEvidence::DirectIdentity {
        session_id: "session-a".into(),
        verified: true,
        evidence_refs: vec!["direct:1".into()],
        protected_digest: DIGEST.into(),
    };
    assert_eq!(
        direct.evaluate().strength,
        McpIdentityStrength::DirectIdentity
    );

    let claim = || McpBindingEvidence::HookStampedClaim {
        claim_id: "claim-1".into(),
        session_id: "session-a".into(),
        issued_at: 10,
        expires_at: 20,
        observed_at: 15,
        call_hash_matches: true,
        parameter_matches: true,
        atomically_consumed: true,
        replayed: false,
        tampered: false,
        rewrite_conflict: false,
        daemon_generation_matches: true,
        evidence_refs: vec!["claim:1".into()],
        protected_digest: DIGEST.into(),
    };
    assert_eq!(
        claim().evaluate().strength,
        McpIdentityStrength::VerifiedHookStampedClaim
    );
    for mutation in 0..7 {
        let mut value = claim();
        if let McpBindingEvidence::HookStampedClaim {
            replayed,
            tampered,
            daemon_generation_matches,
            parameter_matches,
            call_hash_matches,
            observed_at,
            rewrite_conflict,
            ..
        } = &mut value
        {
            match mutation {
                0 => *replayed = true,
                1 => *tampered = true,
                2 => *daemon_generation_matches = false,
                3 => *parameter_matches = false,
                4 => *observed_at = 20,
                5 => *rewrite_conflict = true,
                _ => *call_hash_matches = false,
            }
        }
        assert_eq!(value.evaluate().binding, McpSessionBinding::Unavailable);
    }

    let lease = || McpBindingEvidence::ConnectionLease {
        lease_id: "lease-1".into(),
        session_id: "session-a".into(),
        connection_id: "connection-1".into(),
        expires_at: 20,
        observed_at: 15,
        concurrent_unique: true,
        reconnect_verified: true,
        generation_matches: true,
        replayed: false,
        tampered: false,
        evidence_refs: vec!["lease:1".into()],
        protected_digest: DIGEST.into(),
    };
    assert_eq!(
        lease().evaluate().strength,
        McpIdentityStrength::ProvenConnectionScopedLease
    );
    for mutation in 0..6 {
        let mut value = lease();
        if let McpBindingEvidence::ConnectionLease {
            observed_at,
            concurrent_unique,
            reconnect_verified,
            generation_matches,
            replayed,
            tampered,
            ..
        } = &mut value
        {
            match mutation {
                0 => *observed_at = 20,
                1 => *concurrent_unique = false,
                2 => *reconnect_verified = false,
                3 => *generation_matches = false,
                4 => *replayed = true,
                _ => *tampered = true,
            }
        }
        assert_eq!(value.evaluate().binding, McpSessionBinding::Unavailable);
    }
    let cwd = McpBindingEvidence::CwdOnly {
        cwd_identity: "same-cwd".into(),
        evidence_refs: vec!["cwd:1".into()],
        protected_digest: DIGEST.into(),
    };
    assert_eq!(cwd.evaluate().binding, McpSessionBinding::CwdOnly);
    assert_eq!(
        McpBindingEvidence::Unavailable.evaluate().binding,
        McpSessionBinding::Unavailable
    );
}

#[test]
fn pairing_subagent_close_compact_and_replay_fail_independently() {
    let complete = probe_fixture::fixture("complete");
    let mut cases = Vec::new();
    let mut evidence = complete.clone();
    evidence.capture.as_mut().unwrap().close_reconciled = false;
    cases.push((evidence, GateReason::SourceNotClosed));
    let mut evidence = complete.clone();
    evidence.capture.as_mut().unwrap().subagent_terminals = 0;
    cases.push((evidence, GateReason::SubagentTraceIncomplete));
    let mut evidence = complete.clone();
    evidence.recovery.as_mut().unwrap().pairs[0].post_sequence = Some(9);
    cases.push((evidence, GateReason::RecoveryNotFenced));
    let mut evidence = complete.clone();
    evidence.recovery.as_mut().unwrap().pairs[0].replayed = true;
    cases.push((evidence, GateReason::RecoveryNotFenced));
    let mut evidence = complete.clone();
    let duplicate = evidence.recovery.as_ref().unwrap().pairs[0].clone();
    evidence.recovery.as_mut().unwrap().pairs.push(duplicate);
    cases.push((evidence, GateReason::RecoveryNotFenced));
    for (index, (evidence, reason)) in cases.into_iter().enumerate() {
        let report = report(&evidence);
        if index < 2 {
            assert_eq!(report.capture().reason(), reason);
        } else {
            assert_eq!(report.recovery().reason(), reason);
        }
    }
    let mut evidence = complete;
    evidence.cue.as_mut().unwrap().compact_boundary = CanaryStatus::Failed;
    assert_eq!(
        report(&evidence).active_search_due().reason(),
        GateReason::CueBoundaryUnavailable
    );
}

#[test]
fn exact_occurrence_identity_not_cwd_or_similar_text_controls_merge() {
    let mut evidence = probe_fixture::fixture("complete");
    let observations = &mut evidence.normalization.as_mut().unwrap().observations;
    observations[1].host_trace_lineage_id = "different-fork".into();
    assert_eq!(
        report(&evidence).strong_normalization().reason(),
        GateReason::CorrelationUnproven
    );

    let mut evidence = probe_fixture::fixture("complete");
    evidence.cue.as_mut().unwrap().sessions_isolated = false;
    assert_eq!(
        report(&evidence).active_search_due().reason(),
        GateReason::SessionBindingUnproven
    );

    let mut evidence = probe_fixture::fixture("complete");
    let observations = &mut evidence.normalization.as_mut().unwrap().observations;
    observations.truncate(2);
    observations[0].host_trace_lineage_id = "a:b".into();
    observations[0].host_lane_key = "c".into();
    observations[1].host_trace_lineage_id = "a".into();
    observations[1].host_lane_key = "b:c".into();
    assert_eq!(
        report(&evidence).strong_normalization().reason(),
        GateReason::CorrelationUnproven
    );
}

#[test]
fn duplicate_capture_capability_only_fails_capture_gate() {
    let mut evidence = probe_fixture::fixture("complete");
    let duplicate = evidence.capture.as_ref().unwrap().observed[0];
    evidence.capture.as_mut().unwrap().observed.push(duplicate);
    let report = report(&evidence);
    assert_eq!(
        report.capture().reason(),
        GateReason::EvidenceIntegrityFailed
    );
    assert_eq!(
        [
            report.recovery().result(),
            report.active_search_due().result(),
            report.strong_normalization().result(),
            report.project_policy().result(),
        ],
        [GateResult::Enabled; 4]
    );
}

#[test]
fn project_policy_requires_declared_loaded_current_readback_surface() {
    let complete = probe_fixture::fixture("complete");
    for origin in [
        PolicyCandidateOrigin::RepositoryTrust,
        PolicyCandidateOrigin::Readme,
        PolicyCandidateOrigin::Agents,
        PolicyCandidateOrigin::Comment,
        PolicyCandidateOrigin::SkillText,
        PolicyCandidateOrigin::OrdinaryText,
    ] {
        let mut evidence = complete.clone();
        evidence.policy.as_mut().unwrap().origin = origin;
        assert_eq!(
            report(&evidence).project_policy().reason(),
            GateReason::PolicySurfaceUndeclared
        );
    }

    let mut cases = Vec::new();
    let mut evidence = complete.clone();
    evidence.policy.as_mut().unwrap().host_loaded = false;
    cases.push((evidence, GateReason::PolicyNotLoaded));
    let mut evidence = complete.clone();
    evidence.policy.as_mut().unwrap().current_trust = false;
    cases.push((evidence, GateReason::TrustUnavailable));
    let mut evidence = complete.clone();
    evidence.policy.as_mut().unwrap().revoked = true;
    cases.push((evidence, GateReason::PolicyRevoked));
    let mut evidence = complete.clone();
    evidence.policy.as_mut().unwrap().current = false;
    cases.push((evidence, GateReason::PolicyRevoked));
    let mut evidence = complete;
    evidence.policy.as_mut().unwrap().resolved_scope = None;
    cases.push((evidence, GateReason::PolicyScopeUnresolved));
    for (evidence, reason) in cases {
        assert_eq!(report(&evidence).project_policy().reason(), reason);
    }
}

#[test]
fn fixtures_and_packaging_are_content_free_minimal_inputs() {
    for name in ["empty", "complete"] {
        let text = probe_fixture::fixture_text(name);
        let value: Value = serde_json::from_str(&text).unwrap();
        let mut keys = BTreeSet::new();
        collect_keys(&value, &mut keys);
        for forbidden in ["body", "prompt", "secret", "query", "output", "transcript"] {
            assert!(!keys.contains(forbidden));
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_eq!(
        fs::read_to_string(root.join("packaging/codex/hooks.v1.template.json")).unwrap(),
        "{}\n"
    );
    let mcp = fs::read_to_string(root.join("packaging/codex/mcp.v1.template.toml")).unwrap();
    assert!(toml::from_str::<toml::Table>(&mcp).unwrap().is_empty());
}

fn collect_keys<'a>(value: &'a Value, output: &mut BTreeSet<&'a str>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                output.insert(key);
                collect_keys(value, output);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_keys(value, output);
            }
        }
        _ => {}
    }
}
