//! Explicit qualification of the code-pinned process source, never an experiment executor.
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use evertrace_capture::{CasDigest, CasStore, RuntimeSnapshot, process_source};
use evertrace_codex::{
    adapter_manifest::AdapterKind,
    probe::{
        EvidenceSourceKind, GateResult, HostProbeReport, NormalizationCanaryEvidence,
        NormalizationEvidence, OccurrenceEvidence, ProbeContext, ProbeEvidence,
    },
};
use evertrace_domain::{
    evidence::{
        EvidenceSurface, SourceObservation, SourceReceipt, SourceRole, hex, payload_fingerprint,
    },
    ids::SourceObservationId,
};
use evertrace_store::{CaptureCurrentContext, JournalPayload};
use serde_json::Value;

use super::{
    CanaryIdentity, CanaryWiring, CurrentCanary, HostCanaryDiagnostic, HostCanaryService,
    HostCanaryStatus, canary_diagnostic, canary_file_identity,
};

pub struct ProcessCanaryRequest {
    pub sources: [SourceObservationId; 3],
}

fn contract() -> Option<HostProbeReport> {
    HostProbeReport::native_source_contract(
        &process_source::adapter_version(),
        process_source::ELIGIBLE_EVENTS,
        process_source::FORMAT,
    )
    .ok()
}

struct Fact {
    observation: SourceObservation,
    raw: Vec<u8>,
    value: Value,
}

impl HostCanaryService {
    pub async fn run_process_source(&self, request: ProcessCanaryRequest) -> HostCanaryDiagnostic {
        let Ok(_permit) = self.running.try_lock() else {
            return canary_diagnostic(HostCanaryStatus::Running);
        };
        if let Ok(mut current) = self.process_current.lock() {
            *current = None;
        }
        match self.process_source_inner(request).await {
            Some(current) => {
                let result = current.diagnostic.clone();
                if let Ok(mut stored) = self.process_current.lock() {
                    *stored = Some(current);
                    result
                } else {
                    canary_diagnostic(HostCanaryStatus::Unavailable)
                }
            }
            None => canary_diagnostic(HostCanaryStatus::EvidenceMissing),
        }
    }

    pub(crate) fn process_source_report(&self) -> Option<HostProbeReport> {
        let current = self.process_current.lock().ok()?;
        let current = current.as_ref()?;
        let identity = current.identity.as_ref()?;
        let report = current.report.as_ref()?;
        (matches!(identity.wiring, CanaryWiring::ProcessSource)
            && identity.valid()
            && report.manifest().adapter_manifest_id == contract()?.manifest().adapter_manifest_id
            && report.strong_normalization().result() == GateResult::Enabled)
            .then(|| report.clone())
    }

    async fn process_source_inner(&self, request: ProcessCanaryRequest) -> Option<CurrentCanary> {
        if self.candidate.is_some() {
            return None;
        }
        let snapshot_path = RuntimeSnapshot::snapshot_path(&self.data_root);
        let runtime = RuntimeSnapshot::load(&snapshot_path).ok()?;
        if runtime.effective_config_hash != self.config_hash {
            return None;
        }
        let context = self
            .writer
            .source_canary_context(request.sources, process_source::SOURCE_REVISION.into())
            .await
            .ok()?;
        let cas = CasStore::open_existing(&runtime.cas_dir).ok()?;
        let facts = protected_facts(context, &cas)?;
        let groups = request
            .sources
            .iter()
            .map(|id| {
                let source = facts
                    .iter()
                    .find(|fact| fact.observation.source_observation_id == *id)?;
                let mut group = facts
                    .iter()
                    .filter(|fact| {
                        fact.observation.source_instance_id == source.observation.source_instance_id
                    })
                    .collect::<Vec<_>>();
                group.sort_by_key(|fact| fact.value["sequence"].as_u64());
                Some(group)
            })
            .collect::<Option<Vec<_>>>()?;
        let root = &groups[0];
        let resumed = &groups[1];
        let forked = &groups[2];
        if !generation(root)
            || !generation(resumed)
            || !root[0].value["generation_parent"].is_null()
            || !parent_matches(root, &resumed[0].value, "resume")
        {
            return None;
        }
        let seed = forked
            .iter()
            .find(|fact| fact.observation.source_observation_id == request.sources[2])?;
        let witness = process_source::canary_witness(&seed.raw, &snapshot_path).ok()?;
        // Only the live, nonce-bound export supplies an opening not yet present in L0.
        // It remains probe evidence; do not fabricate or backfill a SourceObservation.
        let opening: Value = serde_json::from_slice(witness.opening_record()).ok()?;
        if !parent_matches(root, &opening, "fork")
            || forked.iter().any(|fact| {
                fact.value["source_epoch"] != opening["source_epoch"]
                    || fact.value["controller"] != opening["controller"]
                    || fact.value["study_key"] != opening["study_key"]
            })
        {
            return None;
        }
        let epochs = [
            root[0].value["source_epoch"].as_str(),
            resumed[0].value["source_epoch"].as_str(),
            opening["source_epoch"].as_str(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if epochs.len() != 3 || epochs.contains(&None) {
            return None;
        }
        let mut files = Vec::new();
        for path in [
            witness.script().to_owned(),
            witness.executable().to_owned(),
            self.config_path.clone(),
            snapshot_path,
        ] {
            files.push((path.clone(), canary_file_identity(&path)?));
        }
        let identity = CanaryIdentity {
            files,
            directories: vec![],
            generation: runtime.generation,
            wiring_hash: String::new(),
            wiring: CanaryWiring::ProcessSource,
        };
        let mut observations = Vec::new();
        let mut refs = BTreeSet::new();
        // The existing gate consumes one SHA-256 over length-framed original observations and replay bytes.
        let mut proof = Vec::new();
        for fact in &facts {
            let reference = fact.observation.source_observation_id.to_string();
            proof.extend_from_slice(&(reference.len() as u64).to_be_bytes());
            proof.extend_from_slice(reference.as_bytes());
            proof.extend_from_slice(&(fact.raw.len() as u64).to_be_bytes());
            proof.extend_from_slice(&fact.raw);
            refs.insert(reference.clone());
            if matches!(
                fact.value["event"].as_str(),
                Some("trial_launch" | "trial_finished")
            ) {
                if !process_source::native_correlation_matches(
                    &fact.raw,
                    &fact.observation.correlation,
                ) {
                    return None;
                }
                observations.push(measurement(fact, false)?);
            }
        }
        let replayed = witness.replayed_record() == seed.raw;
        if !replayed || observations.len() > 31 {
            return None;
        }
        observations.push(measurement(seed, true)?);
        proof.extend_from_slice(&(witness.replayed_record().len() as u64).to_be_bytes());
        proof.extend_from_slice(witness.replayed_record());
        proof.extend_from_slice(&(witness.opening_record().len() as u64).to_be_bytes());
        proof.extend_from_slice(witness.opening_record());
        let retry = retry_evidence(root) && retry_evidence(resumed);
        let original = root
            .iter()
            .find(|fact| fact.value["event"] == "trial_launch")?;
        let mut missing = original.value.clone();
        missing.as_object_mut()?.remove("execution_ordinal");
        let mut conflict = original.value.clone();
        conflict["request_key"] =
            Value::String(evertrace_domain::revision::RevisionId::new_v7().to_string());
        let intact = encode_source(&original.value)?;
        let missing = encode_source(&missing)?;
        let conflict = encode_source(&conflict)?;
        let actual = &original.observation.correlation;
        if !process_source::native_correlation_matches(&intact, actual) {
            return None;
        }
        let fork_isolated =
            root[0].observation.source_instance_id != forked[0].observation.source_instance_id;
        let resume_isolated =
            root[0].observation.source_instance_id != resumed[0].observation.source_instance_id;
        let mut evidence = ProbeEvidence::empty();
        evidence.normalization = Some(NormalizationEvidence {
            evidence_refs: refs.into_iter().collect(),
            observations,
            fork_resume_retry_unique: fork_isolated && resume_isolated && retry,
            replay_rejected: replayed,
            canaries: NormalizationCanaryEvidence {
                fork_isolated,
                resume_isolated,
                retry_ordinal_isolated: retry,
                replay_deduplicated: replayed,
                nonidentity_similarity_not_merged: retry,
                missing_field_rejected: !process_source::native_correlation_matches(
                    &missing, actual,
                ),
                field_conflict_rejected: !process_source::native_correlation_matches(
                    &conflict, actual,
                ),
            },
            protected_digest: CasDigest::for_protected_bytes(&proof).to_string(),
        });
        let report = HostProbeReport::evaluate_native_source(
            &ProbeContext {
                adapter_kind: AdapterKind::Other,
                adapter_revision: process_source::adapter_version(),
                observed_host_version_range: process_source::FORMAT.into(),
                eligible_event_manifest_ref: process_source::ELIGIBLE_EVENTS.into(),
                evidence_source: EvidenceSourceKind::ObservedHostCanary,
            },
            &evidence,
        )
        .ok()?;
        if !identity.valid() {
            return None;
        }
        let status = if report.strong_normalization().result() == GateResult::Enabled {
            HostCanaryStatus::Observed
        } else {
            HostCanaryStatus::EvidenceMissing
        };
        let mut diagnostic = canary_diagnostic(status);
        diagnostic.native_delivery_observed = true;
        diagnostic.qualification = Some(report.qualification());
        Some(CurrentCanary {
            identity: Some(identity),
            diagnostic,
            report: Some(report),
        })
    }
}

fn protected_facts(context: CaptureCurrentContext, cas: &CasStore) -> Option<Vec<Fact>> {
    if context.next_cursor.is_some() || context.items.is_empty() {
        return None;
    }
    let contract = contract()?;
    let mut facts = Vec::new();
    let mut bytes = 0_u64;
    for item in context.items {
        if item.suppressed {
            return None;
        }
        let mut observation: Option<SourceObservation> = None;
        let mut receipt: Option<SourceReceipt> = None;
        let mut surface: Option<EvidenceSurface> = None;
        for row in item.source_rows {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_ref()?.as_str())
                .ok()?
            {
                JournalPayload::SourceObservationRecorded(value) => observation = Some(*value),
                JournalPayload::SourceReceiptRecorded(value) => receipt = Some(*value),
                JournalPayload::EvidenceSurfaceRecorded(value) => surface = Some(*value),
                _ => {}
            }
        }
        let observation = observation?;
        let receipt = receipt?;
        let surface = surface?;
        let (raw, encoded) = cas
            .read_bounded(&CasDigest::from_str(&receipt.cas_ref).ok()?, 131072, 65536)
            .ok()?;
        bytes = bytes.checked_add(encoded + raw.len() as u64)?;
        if bytes > 2 * 1024 * 1024
            || receipt.validate().is_err()
            || observation.validate().is_err()
            || surface.validate().is_err()
            || raw != surface.protected_text.as_bytes()
            || receipt.source_revision.as_str() != process_source::SOURCE_REVISION
            || receipt.parser_revision != process_source::PARSER_REVISION
            || receipt.adapter_revision != process_source::ADAPTER_REVISION
            || receipt.adapter_manifest_ref != contract.manifest().adapter_manifest_id
            || receipt.source_observation_id != observation.source_observation_id
            || observation.source_receipt_ref != receipt.source_receipt_id
            || observation.source_instance_id != receipt.source_instance_id
            || observation.source_revision != receipt.source_revision
            || observation.source_record_identity != receipt.source_record_identity
            || observation.adapter_revision != receipt.adapter_revision
            || observation.correlation.adapter_manifest_ref != receipt.adapter_manifest_ref
            || observation.canonicalization_revision != receipt.canonicalization_revision
            || surface.canonicalization_version != receipt.canonicalization_revision
            || surface.source_observation_revision_ref != observation.source_observation_id
            || receipt.archive_mode != evertrace_domain::evidence::SourceArchiveMode::Exact
            || receipt.unsupported_record_classification.is_some()
            || surface.content_trust != observation.content_trust
            || surface.capture_completeness != observation.capture_completeness
            || receipt.capture_completeness != observation.capture_completeness
            || observation.source_role != SourceRole::Tool
            || surface.source_role != SourceRole::Tool
            || receipt.protected_secret_digest.is_some()
            || !receipt.redaction_spans.is_empty()
            || observation.payload_fingerprint
                != hex(&payload_fingerprint(surface.canonicalization_version, &raw, None).ok()?)
        {
            return None;
        }
        let value = serde_json::from_slice(&raw).ok()?;
        facts.push(Fact {
            observation,
            raw,
            value,
        });
    }
    Some(facts)
}

fn generation(group: &[&Fact]) -> bool {
    let Some(first) = group.first() else {
        return false;
    };
    first.value["event"] == "study_opened"
        && group.iter().enumerate().all(|(index, fact)| {
            fact.value["sequence"].as_u64() == Some(index as u64 + 1)
                && fact.value["format"] == Value::String(process_source::FORMAT.into())
                && fact.value["source_epoch"] == first.value["source_epoch"]
                && fact.value["controller"] == first.value["controller"]
                && fact.value["study_key"] == first.value["study_key"]
        })
}

fn parent_matches(root: &[&Fact], open: &Value, relation: &str) -> bool {
    let Some(close) = root.last() else {
        return false;
    };
    close.value["event"] == "controller_finished"
        && open["event"] == "study_opened"
        && open["sequence"] == 1
        && open["generation_parent"]["relation"] == relation
        && open["generation_parent"]["source_epoch"] == root[0].value["source_epoch"]
        && open["generation_parent"]["close_event"] == close.value["event_key"]
        && open["generation_parent"]["close_sequence"] == close.value["sequence"]
        && open["study_key"] == root[0].value["study_key"]
}

fn measurement(fact: &Fact, replayed: bool) -> Option<OccurrenceEvidence> {
    let value = &fact.observation.correlation;
    Some(OccurrenceEvidence {
        source_ref: fact.observation.source_observation_id.to_string(),
        occurrence_schema_version: value.occurrence_schema_version,
        host_instance_id: value.host_instance_id.clone()?,
        host_trace_lineage_id: value.host_trace_lineage_id.clone()?,
        host_lane_key: value.host_lane_key.clone()?,
        canonical_event_family: "verify".into(),
        native_request_id: value.native_request_id.clone()?,
        physical_execution_ordinal: value.physical_execution_ordinal?,
        similarity_label: None,
        replayed,
    })
}

fn retry_evidence(group: &[&Fact]) -> bool {
    let mut paired = BTreeMap::new();
    for fact in group {
        let Some(request) = fact.value["request_key"].as_str() else {
            continue;
        };
        let Some(ordinal) = fact.value["execution_ordinal"].as_u64() else {
            continue;
        };
        let role = match fact.value["event"].as_str() {
            Some("trial_launch") => 1,
            Some("trial_finished") => 2,
            _ => continue,
        };
        paired
            .entry((request, ordinal))
            .or_insert(BTreeSet::new())
            .insert(role);
    }
    let mut requests = BTreeMap::<&str, BTreeSet<u64>>::new();
    for ((request, ordinal), roles) in paired {
        if roles == BTreeSet::from([1, 2]) {
            requests.entry(request).or_default().insert(ordinal);
        }
    }
    requests
        .values()
        .any(|ordinals| ordinals.len() >= 2 && !ordinals.contains(&0))
}

fn encode_source(value: &Value) -> Option<Vec<u8>> {
    let mut body = value.as_object()?.clone();
    let format = body.remove("format")?;
    let mut raw = format!("{{\"format\":{},", serde_json::to_string(&format).ok()?).into_bytes();
    let rest = serde_json::to_vec(&body).ok()?;
    raw.extend_from_slice(&rest[1..]);
    Some(raw)
}
