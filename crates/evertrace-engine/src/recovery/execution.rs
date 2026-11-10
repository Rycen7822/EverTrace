//! Real execution-namespace canary on an explicitly selected, verified source endpoint.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::{Duration, Instant},
};

use evertrace_capture::{CasDigest, CasStore, RuntimeSnapshot, execution_source};
use evertrace_codex::{
    adapter_manifest::AdapterKind,
    probe::{
        EvidenceSourceKind, GateResult, HostProbeReport, NormalizationCanaryEvidence,
        NormalizationEvidence, OccurrenceEvidence, ProbeContext, ProbeEvidence,
    },
};
use evertrace_domain::evidence::{HostCorrelationEvidence, ObservationRole};

use super::{
    CanaryIdentity, CanaryRun, CanaryWiring, CurrentCanary, HostCanaryDiagnostic,
    HostCanaryService, HostCanaryStatus, canary_diagnostic, canary_file_identity,
};

pub struct ExecutionCanaryRequest {
    pub source_endpoint: PathBuf,
    pub source_executable: PathBuf,
}

impl HostCanaryService {
    /// Explicit qualification only. No model, host process or permanent qualification registry is created.
    pub async fn run_execution_source(
        &self,
        request: ExecutionCanaryRequest,
    ) -> HostCanaryDiagnostic {
        let Ok(_permit) = self.running.try_lock() else {
            return canary_diagnostic(HostCanaryStatus::Running);
        };
        if let Ok(mut current) = self.current.lock() {
            *current = None;
        }
        let mut result = self.run_execution_inner(request).await;
        if result.status == HostCanaryStatus::Observed && self.execution_source_report().is_none() {
            result = canary_diagnostic(HostCanaryStatus::IdentityChanged);
        }
        if let Ok(mut current) = self.current.lock() {
            match current.as_mut() {
                Some(stored) => {
                    stored.diagnostic = HostCanaryDiagnostic {
                        qualification: None,
                        ..result.clone()
                    }
                }
                None => {
                    *current = Some(CurrentCanary {
                        identity: None,
                        diagnostic: result.clone(),
                        report: None,
                    })
                }
            }
        }
        result
    }

    pub(crate) fn execution_source_report(&self) -> Option<HostProbeReport> {
        let current = self.current.lock().ok()?;
        let current = current.as_ref()?;
        let identity = current.identity.as_ref()?;
        let report = current.report.as_ref()?;
        (matches!(identity.wiring, CanaryWiring::ExecutionSource)
            && identity.valid()
            && report.manifest().adapter_version == execution_source::QUALIFIED_ADAPTER_VERSION
            && report.strong_normalization().result() == GateResult::Enabled)
            .then(|| report.clone())
    }

    async fn run_execution_inner(&self, request: ExecutionCanaryRequest) -> HostCanaryDiagnostic {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let unavailable = || canary_diagnostic(HostCanaryStatus::Unavailable);
        if self.candidate.is_some()
            || !request.source_endpoint.is_absolute()
            || !request.source_executable.is_absolute()
            || request.source_endpoint.as_os_str().len() > 4096
            || request.source_executable.as_os_str().len() > 4096
        {
            return unavailable();
        }
        let Ok(runtime) = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&self.data_root))
        else {
            return unavailable();
        };
        if runtime.effective_config_hash != self.config_hash {
            return canary_diagnostic(HostCanaryStatus::IdentityChanged);
        }
        let mut files = Vec::new();
        for path in [
            request.source_executable.clone(),
            self.config_path.clone(),
            RuntimeSnapshot::snapshot_path(&self.data_root),
        ] {
            let Some(identity) = canary_file_identity(&path) else {
                return unavailable();
            };
            files.push((path, identity));
        }
        let identity = CanaryIdentity {
            files,
            directories: vec![],
            generation: runtime.generation,
            wiring_hash: String::new(),
            wiring: CanaryWiring::ExecutionSource,
        };
        let nonce = evertrace_domain::revision::RevisionId::new_v7().to_string();
        let directory = self
            .data_root
            .join("runtime")
            .join(format!("canary-{nonce}"));
        if std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .is_err()
        {
            return unavailable();
        }
        let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
            return unavailable();
        };
        let mut run = CanaryRun {
            service: self.clone(),
            nonce,
            directory: directory.clone(),
            directory_identity: (metadata.dev(), metadata.ino()),
            child: None,
            completed: false,
        };
        let contract = match HostProbeReport::unobserved_source_contract(
            execution_source::ADAPTER_VERSION,
            execution_source::ELIGIBLE_EVENTS,
        ) {
            Ok(value) => value,
            Err(_) => return unavailable(),
        };
        let manifest = contract.manifest().adapter_manifest_id.clone();
        let deadline = Instant::now() + Duration::from_secs(30);
        let collected = tokio::task::spawn_blocking(move || {
            execution_source::canary::collect(
                runtime,
                &request.source_endpoint,
                &request.source_executable,
                &directory,
                &manifest,
                deadline,
            )
        })
        .await;
        let facts = match collected {
            Ok(Ok(facts)) if identity.valid() => facts,
            _ => {
                run.completed = true;
                return canary_diagnostic(HostCanaryStatus::EvidenceMissing);
            }
        };
        let mut observations = Vec::new();
        let mut references = BTreeSet::new();
        let mut deliveries = BTreeSet::new();
        for (reference, correlation) in &facts.measurements {
            let Some(measurement) = occurrence(
                reference,
                correlation,
                !deliveries.insert(reference.clone()),
            ) else {
                run.completed = true;
                return unavailable();
            };
            observations.push(measurement);
            references.insert(reference.clone());
        }
        let retry = self
            .execution_retry_evidence(&mut observations, &mut references)
            .await;
        let mut evidence = ProbeEvidence::empty();
        evidence.normalization = Some(NormalizationEvidence {
            evidence_refs: references.into_iter().collect(),
            observations,
            fork_resume_retry_unique: facts.fork_isolated && facts.resume_isolated && retry,
            replay_rejected: facts.replay_deduplicated,
            canaries: NormalizationCanaryEvidence {
                fork_isolated: facts.fork_isolated,
                resume_isolated: facts.resume_isolated,
                retry_ordinal_isolated: retry,
                replay_deduplicated: facts.replay_deduplicated,
                nonidentity_similarity_not_merged: facts.nonidentity_similarity_not_merged,
                missing_field_rejected: facts.missing_field_rejected,
                field_conflict_rejected: facts.field_conflict_rejected,
            },
            protected_digest: facts.protected_digest,
        });
        let report = HostProbeReport::evaluate(
            &ProbeContext {
                adapter_kind: AdapterKind::Other,
                adapter_revision: execution_source::QUALIFIED_ADAPTER_VERSION.into(),
                observed_host_version_range: "0.166.0".into(),
                eligible_event_manifest_ref: execution_source::ELIGIBLE_EVENTS.into(),
                evidence_source: EvidenceSourceKind::ObservedHostCanary,
            },
            &evidence,
        );
        run.completed = true;
        let Ok(report) = report else {
            return unavailable();
        };
        if !identity.valid() {
            return canary_diagnostic(HostCanaryStatus::IdentityChanged);
        }
        let mut diagnostic = canary_diagnostic(
            if report.strong_normalization().result() == GateResult::Enabled {
                HostCanaryStatus::Observed
            } else {
                HostCanaryStatus::EvidenceMissing
            },
        );
        diagnostic.native_delivery_observed = true;
        diagnostic.qualification = Some(report.qualification());
        if let Ok(mut current) = self.current.lock() {
            *current = Some(CurrentCanary {
                identity: Some(identity),
                diagnostic: HostCanaryDiagnostic {
                    qualification: None,
                    ..diagnostic.clone()
                },
                report: Some(report),
            });
        }
        diagnostic
    }

    // A different logical call is not a retry canary. Reuse protected, admitted real traffic when present.
    async fn execution_retry_evidence(
        &self,
        observations: &mut Vec<OccurrenceEvidence>,
        refs: &mut BTreeSet<String>,
    ) -> bool {
        let Ok(snapshot) = self.writer.project_objects().await else {
            return false;
        };
        let Ok(snapshot) = evertrace_store::CurrentFacts::try_from(snapshot) else {
            return false;
        };
        let Ok(cas) = CasStore::open_existing(self.data_root.join("cas")) else {
            return false;
        };
        let mut remaining = (8 << 20, 8 << 20);
        let mut candidates = Vec::new();
        for (receipt, _) in snapshot
            .source_receipts()
            .filter(|(receipt, _)| {
                receipt.source_revision.as_str() == execution_source::SOURCE_REVISION
                    && matches!(
                        receipt.parser_revision,
                        execution_source::REVISION | execution_source::QUALIFIED_REVISION
                    )
            })
            .take(65)
        {
            if candidates.len() == 64 {
                return false;
            }
            let Some((observation, _)) = snapshot.source_observation(receipt.source_observation_id)
            else {
                return false;
            };
            if !execution_source::is_execution(observation, receipt) {
                continue;
            }
            let Ok(digest) = receipt.cas_ref.parse::<CasDigest>() else {
                return false;
            };
            let Ok((protected, encoded)) = cas.read_bounded(&digest, remaining.0, remaining.1)
            else {
                return false;
            };
            remaining.0 -= encoded;
            remaining.1 -= protected.len() as u64;
            let Some((reference, correlation)) = execution_source::protected_measurement(
                &protected,
                receipt.source_instance_id.as_str(),
                &receipt.adapter_manifest_ref,
                receipt.parser_revision,
            ) else {
                return false;
            };
            let mut canonical = observation.correlation.clone();
            canonical.admission = evertrace_domain::evidence::CorrelationAdmission::Unavailable;
            canonical.strong_gate_receipt_ref = None;
            if reference != receipt.source_ref || correlation != canonical {
                return false;
            }
            if let Some(value) = occurrence(&reference, &correlation, false) {
                candidates.push((value, observation.observation_role));
            }
        }
        // The tuple excludes the physical ordinal on purpose: prove two executions of the same logical request.
        type Logical = (String, String, String, String);
        let mut groups: BTreeMap<Logical, BTreeMap<u32, BTreeSet<u8>>> = BTreeMap::new();
        for (value, role) in &candidates {
            groups
                .entry((
                    value.host_instance_id.clone(),
                    value.host_trace_lineage_id.clone(),
                    value.host_lane_key.clone(),
                    value.native_request_id.clone(),
                ))
                .or_default()
                .entry(value.physical_execution_ordinal)
                .or_default()
                .insert(match role {
                    ObservationRole::Intent => 1,
                    ObservationRole::Result => 2,
                    _ => 0,
                });
        }
        let Some((logical, _)) = groups.iter().find(|(_, ordinals)| {
            ordinals
                .values()
                .filter(|roles| roles.len() == 2 && roles.contains(&1) && roles.contains(&2))
                .count()
                >= 2
        }) else {
            return false;
        };
        for (value, _) in candidates {
            if (
                &value.host_instance_id,
                &value.host_trace_lineage_id,
                &value.host_lane_key,
                &value.native_request_id,
            ) == (&logical.0, &logical.1, &logical.2, &logical.3)
            {
                refs.insert(value.source_ref.clone());
                if !observations.contains(&value) {
                    observations.push(value);
                }
            }
        }
        true
    }
}

fn occurrence(
    reference: &str,
    value: &HostCorrelationEvidence,
    replayed: bool,
) -> Option<OccurrenceEvidence> {
    Some(OccurrenceEvidence {
        source_ref: reference.into(),
        occurrence_schema_version: value.occurrence_schema_version,
        host_instance_id: value.host_instance_id.clone()?,
        host_trace_lineage_id: value.host_trace_lineage_id.clone()?,
        host_lane_key: value.host_lane_key.clone()?,
        canonical_event_family: "other_executable".into(),
        native_request_id: value.native_request_id.clone()?,
        physical_execution_ordinal: value.physical_execution_ordinal?,
        similarity_label: None,
        replayed,
    })
}
