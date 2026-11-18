use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use evertrace_capture::{
    CaptureRecordBody, CasDigest, CasStore, DurableSpool, MaintenanceFence, RuntimeSnapshot,
    SealedSegment, SpoolRecord, decode_validated_record_body,
};
use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{SourceInstanceId, SourceRevision, SourceRevisionMode, SourceRole, hex},
    ids::{CommandId, RepositoryId, SourceObservationId},
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, EventScope, JournalCommand, JournalEventDraft, JournalPayload,
    ProjectionSnapshot, ScopePurgeCurrentView, SourceImportEarlierPrefix, SourceIngestWatermark,
    SourceKind, SourceRevisionRecorded,
};
use thiserror::Error;
use tokio::sync::watch;

use crate::{WriterActorError, WriterHandle, capture::verify_capture_frame_presented};

const MAX_SEGMENTS_PER_DRAIN: usize = 16;
const MAX_SELECTED_OBSERVATIONS: usize = 256;
const CONFIRMED_PREFIX_TAG: &str = "session_import_confirmed_prefix";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DrainProgress {
    pub sealed_segments: usize,
    pub committed_frames: usize,
    pub replayed_frames: usize,
    pub projected_surfaces: usize,
    pub synced_frontier: Option<u64>,
}

// This witness is created only from the sealed L0 row and a live, policy-checked
// Native descendant. The writer rechecks its read set without fencing unrelated L0.
pub(crate) struct SourceSnapshotGuard {
    observation_id: SourceObservationId,
    observation_payload: String,
    receipt_payload: String,
    repository: crate::repository::RepositoryObservationGuard,
    raw: Vec<u8>,
    path: std::path::PathBuf,
    caller_pid: u32,
    deadline: std::time::Instant,
}

impl SourceSnapshotGuard {
    pub(crate) fn observation_id(&self) -> SourceObservationId {
        self.observation_id
    }

    pub(crate) fn identity(&self) -> evertrace_domain::repository::FilesystemIdentity {
        self.repository.identity()
    }

    pub(crate) fn validate(
        &self,
        source: &evertrace_store::CaptureCurrentContext,
        view: evertrace_store::repository::RepositoryCurrentView,
        purged: &BTreeSet<RepositoryId>,
    ) -> Result<(), evertrace_store::StoreError> {
        if std::time::Instant::now() >= self.deadline {
            return Err(evertrace_store::StoreError::InvalidInput);
        }
        let current = source.items.first().filter(|item| !item.suppressed);
        if !current.is_some_and(|item| {
            item.selected.payload_json.as_deref() == Some(self.observation_payload.as_str())
                && item.source_rows.iter().any(|row| {
                    row.object_kind.as_deref() == Some("source_receipt")
                        && row.payload_json.as_deref() == Some(self.receipt_payload.as_str())
                })
        }) {
            return Err(evertrace_store::StoreError::InvalidInput);
        }
        self.repository.validate(view, purged)?;
        if std::time::Instant::now() >= self.deadline {
            return Err(evertrace_store::StoreError::InvalidInput);
        }
        evertrace_capture::process_source::source_launch(&self.raw, &self.path, self.caller_pid)
            .map_err(|_| evertrace_store::StoreError::InvalidInput)?;
        if std::time::Instant::now() >= self.deadline {
            return Err(evertrace_store::StoreError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct EvidenceIngestor {
    snapshot: RuntimeSnapshot,
    writer: WriterHandle,
    effective_config_hash: [u8; 32],
    algorithm_revision: String,
    config: Option<std::sync::Arc<crate::ConfigReloadService>>,
    operation_config: Option<std::sync::Arc<evertrace_domain::config::EffectiveConfig>>,
    scheduler_wakeup: Option<tokio::sync::watch::Sender<u64>>,
    execution_canary: Option<crate::HostCanaryService>,
}

impl EvidenceIngestor {
    pub fn with_execution_canary(mut self, canary: crate::HostCanaryService) -> Self {
        self.execution_canary = Some(canary);
        self
    }

    pub fn with_scheduler_wakeup(mut self, wakeup: tokio::sync::watch::Sender<u64>) -> Self {
        self.scheduler_wakeup = Some(wakeup);
        self
    }
    pub fn with_operation_config(
        mut self,
        config: std::sync::Arc<evertrace_domain::config::EffectiveConfig>,
    ) -> Self {
        self.operation_config = Some(config);
        self
    }
    pub fn with_config(mut self, config: std::sync::Arc<crate::ConfigReloadService>) -> Self {
        self.config = Some(config);
        self
    }
    /// Ordinary daemon consumer. Each unit releases segment claims before
    /// yielding the dispatch read guard, allowing backup and shutdown to drain.
    pub async fn run(
        self,
        dispatch: std::sync::Arc<tokio::sync::RwLock<()>>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), IngestError> {
        let startup_guard = dispatch.read().await;
        if *shutdown.borrow() {
            return Ok(());
        }
        DurableSpool::open_read_only(
            self.snapshot.spool_dir.clone(),
            self.snapshot
                .spool_limits()
                .map_err(|_| IngestError::Snapshot)?,
        )
        .map_err(map_spool)?;
        // Recovery never truncates an unaccounted tail. The paged reader
        // preserves a bad carrier and the Critical lane handles its evidence.
        CasStore::open(self.snapshot.cas_dir.clone()).map_err(|_| IngestError::Cas)?;
        drop(startup_guard);
        let mut cursor = None;
        let mut recovering = false;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let guard = tokio::select! {
                result = shutdown.changed() => { if result.is_err() || *shutdown.borrow() { return Ok(()); } else { continue; } },
                guard = dispatch.read() => guard,
            };
            if *shutdown.borrow() {
                return Ok(());
            }
            let result = self.drain_page(&mut cursor, &shutdown).await;
            drop(guard);
            match result {
                Ok(progress) => {
                    // The journal notification can precede carrier acknowledgement. Wake again only
                    // after durable drain, so optional source consumers do not sleep behind a cleared backlog.
                    if progress.sealed_segments != 0
                        && let Some(wakeup) = &self.scheduler_wakeup
                    {
                        wakeup.send_modify(|value| *value = value.wrapping_add(1));
                    }
                    recovering = false;
                }
                Err(IngestError::Busy) => {}
                Err(IngestError::Recovering) => {
                    if !recovering && let Some(wakeup) = &self.scheduler_wakeup {
                        wakeup.send_modify(|value| *value = value.wrapping_add(1));
                    }
                    recovering = true;
                }
                Err(error) => return Err(error),
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(if recovering { 1000 } else { 100 })) => {},
                result = shutdown.changed() => { if result.is_err() || *shutdown.borrow() { return Ok(()); } },
            }
        }
    }

    async fn drain_page(
        &self,
        cursor: &mut Option<evertrace_capture::spool::SpoolReadCursor>,
        shutdown: &watch::Receiver<bool>,
    ) -> Result<DrainProgress, IngestError> {
        let mut spool = DurableSpool::open_read_only(
            self.snapshot.spool_dir.clone(),
            self.snapshot
                .spool_limits()
                .map_err(|_| IngestError::Snapshot)?,
        )
        .map_err(map_spool)?;
        let recovering = !spool.pending_gap_markers().map_err(map_spool)?.is_empty()
            || std::fs::read_dir(self.snapshot.spool_dir.join("quarantine"))
                .map_err(|_| IngestError::Spool)?
                .next()
                .transpose()
                .map_err(|_| IngestError::Spool)?
                .is_some();
        // Markers do not authorize discarding a carrier or upgrading capture,
        // but healthy independent records can supply the missing attribution.
        if cursor.is_none() {
            spool
                .seal_active(self.snapshot.generation)
                .map_err(map_spool)?;
        }
        let segments = match spool.ingest_page(cursor.as_ref()) {
            Err(evertrace_capture::SpoolError::RecoveryRequired) => {
                *cursor = None;
                return Err(IngestError::Recovering);
            }
            result => result.map_err(map_spool)?,
        };
        if segments.is_empty() {
            return if recovering {
                Err(IngestError::Recovering)
            } else {
                Ok(DrainProgress::default())
            };
        }
        let next = segments[0].continuation().map_err(map_spool)?;
        let result = match self
            .drain_segments(&spool, segments, None, true, Some(shutdown))
            .await
        {
            Err(IngestError::Recovering) => {
                // Semantic quarantine also invalidates a continuation into this carrier.
                *cursor = None;
                return Err(IngestError::Recovering);
            }
            result => result?,
        };
        if *shutdown.borrow() {
            return Ok(result);
        }
        *cursor = next;
        if recovering {
            Err(IngestError::Recovering)
        } else {
            Ok(result)
        }
    }
    pub fn new(
        snapshot: RuntimeSnapshot,
        writer: WriterHandle,
        effective_config_hash: [u8; 32],
        algorithm_revision: impl Into<String>,
    ) -> Result<Self, IngestError> {
        snapshot.validate().map_err(|_| IngestError::Snapshot)?;
        let algorithm_revision = algorithm_revision.into();
        if algorithm_revision.is_empty() || algorithm_revision.len() > 256 {
            return Err(IngestError::InvalidRecord);
        }
        Ok(Self {
            snapshot,
            writer,
            effective_config_hash,
            algorithm_revision,
            config: None,
            operation_config: None,
            scheduler_wakeup: None,
            execution_canary: None,
        })
    }

    pub async fn drain_once(&self) -> Result<DrainProgress, IngestError> {
        self.drain_selected(None).await
    }

    pub async fn drain_observations_once(
        &self,
        observation_ids: &[SourceObservationId],
    ) -> Result<DrainProgress, IngestError> {
        if observation_ids.is_empty()
            || observation_ids.len() > MAX_SELECTED_OBSERVATIONS
            || observation_ids
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != observation_ids.len()
        {
            return Err(IngestError::InvalidRecord);
        }
        let selected = observation_ids
            .iter()
            .map(ToString::to_string)
            .collect::<std::collections::BTreeSet<_>>();
        self.drain_selected(Some(&selected)).await
    }

    async fn drain_selected(
        &self,
        selected: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<DrainProgress, IngestError> {
        let (mut spool, recovery) = DurableSpool::open(
            self.snapshot.spool_dir.clone(),
            self.snapshot
                .spool_limits()
                .map_err(|_| IngestError::Snapshot)?,
        )
        .map_err(|_| IngestError::Spool)?;
        if recovery.repaired_tail_bytes != 0 || selected.is_none() && !recovery.gaps.is_empty() {
            return Err(IngestError::Recovering);
        }
        spool
            .seal_active(self.snapshot.generation)
            .map_err(|_| IngestError::Spool)?;
        let segment_limit = match selected {
            Some(_) => {
                usize::try_from(self.snapshot.max_main_files).map_err(|_| IngestError::Snapshot)?
            }
            None => MAX_SEGMENTS_PER_DRAIN,
        };
        let segments = spool
            .sealed_segments(segment_limit)
            .map_err(|_| IngestError::Spool)?;
        self.drain_segments(&spool, segments, selected, false, None)
            .await
    }

    async fn verify_namespace_support(
        &self,
        original: &crate::capture::VerifiedCapture,
        cas: &CasStore,
        remaining: &mut (u64, u64),
    ) -> Result<(), IngestError> {
        use evertrace_domain::evidence::SourceLocalEvidence;
        let Some(SourceLocalEvidence::NamespaceWitness {
            supported_call,
            supported_observation_refs,
            ..
        }) = &original.body.source_local_evidence
        else {
            return Ok(());
        };
        let snapshot = self.writer.project().await.map_err(map_writer_error)?;
        let view =
            evertrace_store::projections::RecoveryEvidenceCurrentView::from_snapshot(&snapshot)
                .map_err(|_| IngestError::StoreCorrupt)?;
        for id in supported_observation_refs {
            let observation = view.observation(*id).ok_or(IngestError::InvalidRecord)?;
            let receipt = view
                .receipt_for_observation(*id)
                .ok_or(IngestError::InvalidRecord)?;
            let digest = CasDigest::from_str(&receipt.cas_ref).map_err(|_| IngestError::Cas)?;
            let (bytes, encoded) = cas
                .read_bounded(&digest, remaining.0, remaining.1)
                .map_err(|_| IngestError::Cas)?;
            remaining.0 -= encoded;
            remaining.1 -= bytes.len() as u64;
            let call = evertrace_codex::hook_input::native_call_from_raw(
                &bytes,
                observation.observation_role,
            )
            .ok_or(IngestError::InvalidRecord)?;
            let mut claimed = supported_call.clone();
            claimed.namespace_witness = None;
            if call != claimed || receipt.protected_length != bytes.len() as u64 {
                return Err(IngestError::InvalidRecord);
            }
        }
        Ok(())
    }

    fn freeze_namespace_probe(
        &self,
        original: &crate::capture::VerifiedCapture,
        records: &[SpoolRecord],
        cas: &CasStore,
        remaining: &mut (u64, u64),
    ) -> Result<(), IngestError> {
        use evertrace_domain::evidence::{
            CaptureCompleteness, ContentTrust, IdentityStrength, ObservationRole,
            SourceLocalEvidence,
        };
        let call = original
            .native_call
            .as_ref()
            .ok_or(IngestError::InvalidRecord)?;
        let record_id = format!("native-namespace:{}", original.body.command_id);
        let mut found = records
            .iter()
            .filter(|record| record.spool_record_id == record_id);
        if let Some(record) = found.next() {
            if found.next().is_some() {
                return Err(IngestError::InvalidRecord);
            }
            let (body, _) =
                decode_validated_record_body(record).map_err(|_| IngestError::InvalidRecord)?;
            let evidence = body
                .source_local_evidence
                .as_ref()
                .ok_or(IngestError::InvalidRecord)?;
            let SourceLocalEvidence::NamespaceWitness {
                supported_call,
                supported_observation_refs,
                ..
            } = evidence
            else {
                return Err(IngestError::InvalidRecord);
            };
            if supported_call != call
                || supported_observation_refs != &[original.observation.source_observation_id]
                || body.source_instance_id.as_str() != record_id
            {
                return Err(IngestError::InvalidRecord);
            }
            let digest = CasDigest::from_str(&body.cas_ref).map_err(|_| IngestError::Cas)?;
            let (bytes, encoded) = cas
                .read_bounded(&digest, remaining.0, remaining.1)
                .map_err(|_| IngestError::Cas)?;
            remaining.0 -= encoded;
            remaining.1 -= bytes.len() as u64;
            let raw: SourceLocalEvidence =
                serde_json::from_slice(&bytes).map_err(|_| IngestError::InvalidRecord)?;
            if &raw != evidence {
                return Err(IngestError::InvalidRecord);
            }
            return Ok(());
        }
        let Some(witness) = crate::repository::freeze_native_namespace(call) else {
            return Ok(());
        };
        let evidence = SourceLocalEvidence::NamespaceWitness {
            witness,
            supported_call: call.clone(),
            supported_observation_refs: vec![original.observation.source_observation_id],
        };
        let raw_payload = serde_json::to_vec(&evidence).map_err(|_| IngestError::InvalidRecord)?;
        let mut correlation = original.body.correlation.clone();
        correlation.pairing_role = ObservationRole::StateProbe;
        correlation.native_request_id = None;
        correlation.field_provenance.clear();
        let input = evertrace_capture::CaptureRecordInput {
            source_local_evidence: Some(evidence),
            spool_record_id: Some(record_id.clone()),
            source_observation_id_hint: None,
            source_instance_id: record_id.clone(),
            source_revision: "initial".into(),
            source_record_identity: None,
            identity_strength: Some(IdentityStrength::SynthesizedBestEffort),
            source_kind: original.body.source_kind,
            identity_domain: original.body.identity_domain.clone(),
            source_ref: record_id,
            session_ref: call.session_id.clone(),
            turn_ref: Some(call.turn_id.clone()),
            tool_ref: Some(call.request_id.clone()),
            source_sequence: 0,
            source_sequence_origin: Some(0),
            task_id: None,
            repository_instance_id: None,
            worktree_instance_id: None,
            source_byte_range: None,
            source_revision_mode: SourceRevisionMode::Append,
            previous_source_revision: None,
            close_watermark: None,
            observation_role: ObservationRole::StateProbe,
            correlation,
            scope_effect_claims: vec![],
            lifecycle: None,
            unsupported_record_classification: None,
            source_role: SourceRole::Host,
            content_trust: ContentTrust::Observed,
            capture_completeness: CaptureCompleteness::Partial,
            surface_eligible: false,
            adapter_revision: original.body.adapter_revision,
            adapter_manifest_ref: original.body.adapter_manifest_ref.clone(),
            eligible_event_manifest_ref: original.body.eligible_event_manifest_ref.clone(),
            parser_revision: original.body.parser_revision,
            canonicalization_revision: original.body.canonicalization_revision,
            event_time_us: None,
            event_time_provenance: None,
            raw_payload,
        };
        let Ok(mut runtime) =
            evertrace_capture::CaptureRuntime::open_for_admission(self.snapshot.clone())
        else {
            return Ok(());
        };
        let _ = runtime
            .capture(input)
            .map_err(|_| IngestError::InvalidRecord)?;
        Ok(())
    }

    /// Observe a held source trial through the actual Hook connection, not caller facts.
    pub async fn observe_process_source(
        &self,
        observation_id: SourceObservationId,
        caller_pid: u32,
        request_deadline: std::time::Instant,
    ) -> Result<bool, IngestError> {
        use crate::repository::{
            GitOid, HostTrustDecision, ProbeLimits, RepositoryResolveInput, ResolutionKind,
        };
        use evertrace_capture::process_source;
        use std::{
            path::Path,
            time::{Duration, Instant},
        };
        let Some(authority) = self
            .execution_canary
            .as_ref()
            .and_then(|value| value.execution_scope_source())
        else {
            return Ok(false);
        };
        // Admit durable Native starts with the child cue. Selective child-only intake can leave
        // its live parent queued behind unrelated records until the process carrier has exited.
        let spool = DurableSpool::open_read_only(
            &self.snapshot.spool_dir,
            self.snapshot
                .spool_limits()
                .map_err(|_| IngestError::Snapshot)?,
        )
        .map_err(map_spool)?;
        let records = match spool.read_durable_records(MAX_SEGMENTS_PER_DRAIN, 64 * 1024 * 1024) {
            Ok(records) => records,
            Err(evertrace_capture::SpoolError::ResourceExhausted) => {
                self.drain_once().await?;
                return Ok(false);
            }
            Err(error) => return Err(map_spool(error)),
        };
        let mut observations = BTreeSet::from([observation_id]);
        for record in records {
            let Ok((body, id)) = decode_validated_record_body(&record) else {
                continue;
            };
            if evertrace_capture::execution_source::is_source_revision(
                body.source_revision.as_str(),
            ) && evertrace_capture::execution_source::Profile::from_revision(
                body.parser_revision,
            ) == Some(evertrace_capture::execution_source::Profile::Context)
                && body.observation_role == evertrace_domain::evidence::ObservationRole::Intent
            {
                observations.insert(id);
                if observations.len() > MAX_SELECTED_OBSERVATIONS {
                    break;
                }
            }
        }
        if observations.len() > MAX_SELECTED_OBSERVATIONS {
            self.drain_once().await?;
            return Ok(false);
        }
        self.drain_observations_once(&observations.into_iter().collect::<Vec<_>>())
            .await?;
        let cas = CasStore::open_existing(&self.snapshot.cas_dir).map_err(|_| IngestError::Cas)?;
        let snapshot_path = RuntimeSnapshot::snapshot_path(
            self.snapshot
                .data_dir()
                .map_err(|_| IngestError::Snapshot)?,
        );
        for _ in 0..3 {
            let selected = self
                .writer
                .capture_current_context(None, Some(observation_id.to_string()), 1)
                .await
                .map_err(map_writer_error)?;
            let Some(item) = selected.items.first().filter(|item| !item.suppressed) else {
                return Ok(false);
            };
            let JournalPayload::SourceObservationRecorded(observation) = serde_json::from_str(
                item.selected
                    .payload_json
                    .as_deref()
                    .ok_or(IngestError::InvalidRecord)?,
            )
            .map_err(|_| IngestError::InvalidRecord)?
            else {
                return Err(IngestError::InvalidRecord);
            };
            let Some(row) = item
                .source_rows
                .iter()
                .find(|row| row.object_kind.as_deref() == Some("source_receipt"))
            else {
                return Ok(false);
            };
            let JournalPayload::SourceReceiptRecorded(receipt) = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(IngestError::InvalidRecord)?,
            )
            .map_err(|_| IngestError::InvalidRecord)?
            else {
                return Err(IngestError::InvalidRecord);
            };
            if !matches!(
                receipt.source_revision.as_str(),
                process_source::SOURCE_REVISION | process_source::IMAGE_SOURCE_REVISION
            ) || receipt.source_observation_id != observation_id
                || observation.source_observation_id != observation_id
            {
                return Ok(false);
            }
            if receipt.source_revision.as_str() == process_source::IMAGE_SOURCE_REVISION
                || observation.observation_role
                    == evertrace_domain::evidence::ObservationRole::Result
            {
                return Ok(observation.content_trust
                    == evertrace_domain::evidence::ContentTrust::Observed
                    && observation.capture_completeness
                        == evertrace_domain::evidence::CaptureCompleteness::Complete);
            }
            let command_id = source_snapshot_command_id(observation_id, receipt.recorded_at_us)?;
            if self
                .writer
                .committed_command(command_id)
                .await
                .map_err(map_writer_error)?
                .is_some()
            {
                return Ok(false);
            }
            let digest = CasDigest::from_str(&receipt.cas_ref).map_err(|_| IngestError::Cas)?;
            let (raw, _) = cas
                .read_bounded(&digest, 128 * 1024, 65_536)
                .map_err(|_| IngestError::Cas)?;
            let authority = authority.clone();
            let path = snapshot_path.clone();
            let located = tokio::task::spawn_blocking(move || {
                let launch = process_source::source_launch(&raw, &path, caller_pid).ok()?;
                let (pid, start) = launch.controller();
                let namespace = authority.observe_controller(pid, start)?;
                if Path::new(&namespace.cwd) != launch.directory() {
                    return None;
                }
                let deadline = (Instant::now() + Duration::from_millis(500)).min(request_deadline);
                let location =
                    crate::repository::workspace_git_location(Path::new(&namespace.cwd), deadline)
                        .ok()??;
                let trust = namespace.trust(location.worktree_path.to_str()?, deadline);
                if trust.state != evertrace_codex::policy::RepositoryTrustState::Trusted {
                    return None;
                }
                let mut references = vec![
                    receipt.source_ref,
                    namespace.evidence_ref(&observation_id.to_string()),
                ];
                references.extend(trust.evidence_refs);
                Some((launch, namespace, location, references, raw, path))
            })
            .await
            .map_err(|_| IngestError::Store)?;
            let Some((launch, namespace, location, references, raw, path)) = located else {
                return Ok(false);
            };
            let (view, purged) = self
                .writer
                .repository_resolution_context(location.common_dir_filesystem)
                .await
                .map_err(map_writer_error)?;
            if view.repositories.values().any(|row| {
                !crate::repository::repository_read_gate(row, purged.contains(&row.repository_id))
            }) {
                return Ok(false);
            }
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| IngestError::InvalidRecord)?
                    .as_micros(),
            )
            .map_err(|_| IngestError::InvalidRecord)?;
            let identity = location.common_dir_filesystem;
            let resolved = tokio::task::spawn_blocking(move || {
                let heads = view
                    .snapshots
                    .values()
                    .filter_map(|row| row.head_oid.as_deref())
                    .map(GitOid::parse)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                // Time spent waiting for the writer is not Git probe time. Both
                // stages still share the Hook request deadline and live-source guard.
                let deadline = (Instant::now() + Duration::from_millis(500)).min(request_deadline);
                let evidence = crate::repository::with_probe_deadline(deadline, || {
                    crate::repository::probe_repository(
                        Path::new(&namespace.cwd),
                        HostTrustDecision::Trusted,
                        &references,
                        now,
                        &ProbeLimits::default(),
                        &view.known_admin_paths(),
                        &heads,
                    )
                })
                .ok()?;
                let (commit, tree) = launch.anchor();
                if evidence.unavailable_reason.is_some()
                    || !namespace.valid()
                    || evidence.head_oid.as_ref().map(GitOid::as_str) != Some(commit)
                    || evidence.tree_oid.as_ref().map(GitOid::as_str) != Some(tree)
                    || evidence.common_dir_filesystem != Some(location.common_dir_filesystem)
                    || evidence.git_dir.as_deref().map(Path::new)
                        != Some(location.git_dir.as_path())
                {
                    return None;
                }
                let incomplete = view.repositories.keys().copied().collect();
                let input = RepositoryResolveInput {
                    view: &view,
                    evidence: &evidence,
                    derived_from_hint: None,
                };
                let resolution = input.resolve_with_incomplete_history(&incomplete).ok()?;
                let reference = namespace.evidence_ref(&observation_id.to_string());
                let resolution = crate::repository::complete_repository_source_start(
                    &input, &reference, resolution,
                )
                .ok()?;
                if !matches!(
                    resolution.kind,
                    Some(
                        ResolutionKind::Create
                            | ResolutionKind::Successor
                            | ResolutionKind::NoDelta
                    )
                ) {
                    return None;
                }
                if !namespace.valid()
                    || process_source::source_launch(&raw, &path, caller_pid).is_err()
                {
                    return None;
                }
                Some((resolution.payloads(), namespace, view, raw, path))
            })
            .await
            .map_err(|_| IngestError::Store)?;
            let Some((payloads, namespace, view, raw, path)) = resolved else {
                return Ok(false);
            };
            if payloads.is_empty() {
                return Ok(false);
            }
            let events = payloads
                .into_iter()
                .map(|payload| {
                    let mut event = JournalEventDraft::runtime(
                        now,
                        self.snapshot.effective_config_hash,
                        "process-source-snapshot-v1",
                        payload,
                    );
                    event.causation_id = Some(observation_id.to_string());
                    event
                })
                .collect();
            if !namespace.valid() {
                return Ok(false);
            }
            let command =
                JournalCommand::new(command_id, events).map_err(|_| IngestError::InvalidRecord)?;
            let guard = SourceSnapshotGuard {
                observation_id,
                observation_payload: item
                    .selected
                    .payload_json
                    .as_deref()
                    .map(str::to_owned)
                    .ok_or(IngestError::InvalidRecord)?,
                receipt_payload: row
                    .payload_json
                    .as_deref()
                    .map(str::to_owned)
                    .ok_or(IngestError::InvalidRecord)?,
                repository: crate::repository::RepositoryObservationGuard::new(
                    namespace, identity, view, purged,
                ),
                raw,
                path,
                caller_pid,
                deadline: request_deadline,
            };
            match self
                .writer
                .commit_source_snapshot(command, now, guard)
                .await
            {
                Ok(outcome) => return Ok(!outcome.replayed),
                Err(WriterActorError::StaleFrontier) => continue,
                Err(WriterActorError::InvalidInput) => return Ok(false),
                Err(error) => return Err(map_writer_error(error)),
            }
        }
        Ok(false)
    }

    async fn observe_live_process(
        &self,
        verified: &mut crate::capture::VerifiedCapture,
    ) -> Result<(), IngestError> {
        use evertrace_capture::process_source;
        use evertrace_domain::evidence::{CaptureCompleteness, ContentTrust, ObservationRole};
        let body = &verified.body;
        let image = body.source_revision.as_str() == process_source::IMAGE_SOURCE_REVISION;
        if !image
            && (body.source_revision.as_str() != process_source::SOURCE_REVISION
                || (body.adapter_revision, body.parser_revision)
                    != (
                        process_source::ADAPTER_REVISION,
                        process_source::PARSER_REVISION,
                    )
                || body.observation_role != ObservationRole::Result
                || body.correlation.native_request_id.is_none()
                || body.correlation.physical_execution_ordinal.is_none())
        {
            return Ok(());
        }
        let Some(surface) = verified.surface.as_ref() else {
            return Ok(());
        };
        let raw = surface.protected_text.as_bytes().to_vec();
        let snapshot = RuntimeSnapshot::snapshot_path(
            self.snapshot
                .data_dir()
                .map_err(|_| IngestError::Snapshot)?,
        );
        let identity = body.source_record_identity.as_str().to_owned();
        let revision = body.adapter_revision;
        let observed = tokio::task::spawn_blocking(move || {
            if image {
                process_source::verify_runtime_image(&raw, &snapshot, revision)
                    .is_ok_and(|value| value == identity)
            } else {
                process_source::verify_native_terminal(&raw, &snapshot).is_ok()
            }
        })
        .await
        .map_err(|_| IngestError::Store)?;
        if observed {
            verified.receipt.capture_completeness = CaptureCompleteness::Complete;
            verified.observation.capture_completeness = CaptureCompleteness::Complete;
            verified.observation.content_trust = ContentTrust::Observed;
            if let Some(surface) = &mut verified.surface {
                surface.capture_completeness = CaptureCompleteness::Complete;
                surface.content_trust = ContentTrust::Observed;
            }
        }
        Ok(())
    }

    async fn normalize_live_native(
        &self,
        verified: &crate::capture::VerifiedCapture,
        spool: &DurableSpool,
        occurred_at_us: i64,
    ) -> Result<(), IngestError> {
        use crate::capture::{
            CAPTURE_ALGORITHM_REVISION, ReconcileError, ReconcileInput,
            normalize_live_observation_once,
        };
        use evertrace_capture::execution_source::{Profile, is_execution};
        let process_terminal = verified.receipt.source_revision.as_str()
            == evertrace_capture::process_source::SOURCE_REVISION
            && (
                verified.receipt.adapter_revision,
                verified.receipt.parser_revision,
            ) == (
                evertrace_capture::process_source::ADAPTER_REVISION,
                evertrace_capture::process_source::PARSER_REVISION,
            )
            && verified.observation.observation_role
                == evertrace_domain::evidence::ObservationRole::Result
            && verified.observation.content_trust
                == evertrace_domain::evidence::ContentTrust::Observed
            && verified.observation.capture_completeness
                == evertrace_domain::evidence::CaptureCompleteness::Complete
            && verified.observation.correlation.exact_key().is_some();
        if (!process_terminal
            && (Profile::from_revision(verified.receipt.parser_revision) != Some(Profile::Context)
                || !is_execution(&verified.observation, &verified.receipt)))
            || !spool.pending_gap_markers().map_err(map_spool)?.is_empty()
            || std::fs::read_dir(self.snapshot.spool_dir.join("quarantine"))
                .map_err(|_| IngestError::Spool)?
                .next()
                .is_some()
        {
            return Ok(());
        }
        let Some(canary) = &self.execution_canary else {
            return Ok(());
        };
        let (report, source) = if process_terminal {
            let Some(report) = canary.process_source_report().filter(|report| {
                report.manifest().adapter_manifest_id == verified.receipt.adapter_manifest_ref
            }) else {
                return Ok(());
            };
            // The source owns its namespace; no directory or authority is inherited from the parent.
            (report, None)
        } else {
            let Some(source) = canary.execution_scope_source() else {
                return Ok(());
            };
            let Some(report) = canary.execution_source_report() else {
                return Ok(());
            };
            (report, Some(source))
        };
        let input = ReconcileInput {
            runtime_snapshot: self.snapshot.clone(),
            adapter_manifests: vec![report.manifest().clone()],
            liveness: Vec::new(),
            reconciled_gaps: Vec::new(),
            reconciled_outages: Vec::new(),
            independent_source_reconciliations: Vec::new(),
            effective_config_hash: self.snapshot.effective_config_hash,
            algorithm_revision: CAPTURE_ALGORITHM_REVISION.to_owned(),
            occurred_at_us,
            max_items: 3,
        };
        match normalize_live_observation_once(
            input,
            &self.writer,
            verified.observation.source_observation_id,
            source,
        )
        .await
        {
            Ok(_)
            | Err(
                ReconcileError::Busy
                | ReconcileError::StaleFrontier
                | ReconcileError::Spool
                | ReconcileError::Manifest,
            ) => Ok(()),
            Err(_) => Err(IngestError::Store),
        }
    }

    async fn drain_segments(
        &self,
        spool: &DurableSpool,
        segments: Vec<SealedSegment>,
        selected: Option<&BTreeSet<String>>,
        bounded: bool,
        shutdown: Option<&watch::Receiver<bool>>,
    ) -> Result<DrainProgress, IngestError> {
        if segments.is_empty() {
            return Ok(DrainProgress::default());
        }
        let config = match self.config.as_ref() {
            Some(config) => Some(config.admit().await.map_err(|_| IngestError::Snapshot)?),
            None => self.operation_config.clone(),
        };
        let effective_config_hash = config
            .as_ref()
            .map_or(self.effective_config_hash, |config| config.hash());
        let cas =
            CasStore::open_existing(self.snapshot.cas_dir.clone()).map_err(|_| IngestError::Cas)?;
        let mut progress = DrainProgress::default();
        let mut prefix_projection = None;
        let mut prefix_states = BTreeMap::new();
        let mut terminal_segments = Vec::new();
        // One bounded immutable-witness recovery scan per drain, never one
        // scan per frame or a periodic search through acknowledged history.
        let mut namespace_records = None;
        let mut remaining = if bounded {
            (64 * 1024 * 1024, 64 * 1024 * 1024)
        } else {
            (u64::MAX, u64::MAX)
        };
        for segment in segments {
            // Keep the original validation barrier even for source-local input
            // without repository IDs. The predicate needs only scoped purge
            // membership, not a transferred full objects snapshot.
            let purge_frontier = self
                .writer
                .sync_objects_frontier()
                .await
                .map_err(map_writer_error)?;
            let repository_ids = segment
                .frames()
                .iter()
                .filter(|frame| {
                    selected.is_none_or(|ids| ids.contains(&frame.record.source_observation_id))
                })
                // Leave malformed input to its original per-frame error path.
                .map_while(|frame| canonical_body(&frame.record).ok())
                .filter_map(|body| body.repository_instance_id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut purged = BTreeSet::new();
            // RepositoryReadContext has a fixed 64-repository request bound.
            for ids in repository_ids.chunks(64) {
                let context = self
                    .writer
                    .repository_read_context(ids.iter().copied().collect())
                    .await
                    .map_err(map_writer_error)?;
                if context.frontier < purge_frontier {
                    return Err(IngestError::StoreCorrupt);
                }
                purged.extend(context.purged);
            }
            let mut committed = 0_usize;
            let mut invalid = false;
            let mut terminal = Vec::new();
            let mut shared_maintenance = None;
            let mut replay_batch = BTreeMap::new();
            for (frame_index, frame) in segment.frames().iter().enumerate() {
                // Finish an admitted journal command before observing shutdown.
                // A partial page is never acknowledged: restart replays its
                // original command IDs, including any already committed frame.
                if shutdown.is_some_and(|signal| *signal.borrow()) {
                    return Ok(progress);
                }
                if frame_index % evertrace_store::MAX_COMMITTED_COMMAND_READ == 0 {
                    // Only retain this bounded chunk. A missing entry still uses
                    // the single lookup below, including same-page duplicates
                    // committed after prefetch. No payload is trusted from CAS
                    // or spool in place of the validated journal command.
                    let ids = segment.frames()[frame_index..]
                        .iter()
                        .take(evertrace_store::MAX_COMMITTED_COMMAND_READ)
                        .filter(|frame| {
                            selected
                                .is_none_or(|ids| ids.contains(&frame.record.source_observation_id))
                        })
                        .map_while(|frame| canonical_body(&frame.record).ok())
                        .filter(|body| !capture_is_purged(body, &purged))
                        .map(|body| body.command_id)
                        .collect();
                    replay_batch = self
                        .writer
                        .committed_commands(ids)
                        .await
                        .map_err(map_writer_error)?;
                }
                if selected.is_some_and(|ids| !ids.contains(&frame.record.source_observation_id)) {
                    continue;
                }
                let body = match canonical_body(&frame.record) {
                    Ok(body) => body,
                    Err(IngestError::InvalidRecord | IngestError::IdentityMismatch) if bounded => {
                        invalid = true;
                        break;
                    }
                    Err(error) => return Err(error),
                };
                if capture_is_purged(&body, &purged) {
                    terminal.push(body);
                    continue;
                }
                if shared_maintenance.is_none() {
                    let data_dir = self
                        .snapshot
                        .data_dir()
                        .map_err(|_| IngestError::Snapshot)?;
                    let fence = MaintenanceFence::open(data_dir).map_err(|_| IngestError::Cas)?;
                    shared_maintenance = Some(fence.shared().map_err(|_| IngestError::Cas)?);
                }
                let mut verified = match verify_capture_frame_presented(
                    frame,
                    &cas,
                    &mut remaining,
                    config.as_ref().map(|config| &config.config().capture),
                ) {
                    Ok(verified) => verified,
                    Err(IngestError::InvalidRecord | IngestError::IdentityMismatch) if bounded => {
                        invalid = true;
                        break;
                    }
                    Err(error) => return Err(error),
                };
                let surface_count = usize::from(verified.surface.is_some());
                let recorded_at_us = verified.body.recorded_at_us;
                let (digest, watermark) =
                    if evertrace_store::session_import::is_session_import_source(
                        verified.body.source_instance_id.as_str(),
                    ) {
                        let range = verified
                            .receipt
                            .source_byte_range
                            .as_ref()
                            .ok_or(IngestError::InvalidRecord)?;
                        if range.end != verified.body.source_sequence || range.end <= range.start {
                            return Err(IngestError::InvalidRecord);
                        }
                        let key = (
                            verified.body.source_instance_id.as_str().to_owned(),
                            verified.body.source_revision.as_str().to_owned(),
                        );
                        if !prefix_states.contains_key(&key) {
                            if prefix_projection.is_none() {
                                prefix_projection = Some(
                                    self.writer
                                        .project_objects()
                                        .await
                                        .map_err(map_writer_error)?,
                                );
                            }
                            let context = self
                                .writer
                                .session_import_context(&key.0)
                                .await
                                .map_err(map_writer_error)?;
                            let origin_fence = context
                                .filter(|context| {
                                    context.current.metadata.source_revision.as_str() == key.1
                                })
                                .and_then(|context| context.current.metadata.prospective_origin)
                                .and_then(|origin| origin.record_start);
                            let projected = projected_confirmed_prefix(
                                prefix_projection
                                    .as_ref()
                                    .ok_or(IngestError::StoreCorrupt)?,
                                &verified.body.source_instance_id,
                                &verified.body.source_revision,
                                origin_fence,
                            )?;
                            prefix_states.insert(key.clone(), projected);
                        }
                        let state = prefix_states.get(&key).ok_or(IngestError::StoreCorrupt)?;
                        let local_exact = state.local_exact.get(&range.end).cloned();
                        let is_committed =
                            state.committed_watermark.as_ref().is_some_and(|value| {
                                match value.earlier_prefix.as_ref() {
                                    Some(prefix) if range.end <= prefix.fence_byte => {
                                        range.end <= prefix.through_byte
                                    }
                                    Some(prefix) => {
                                        range.start >= prefix.fence_byte
                                            && value.confirmed_prefix_digest.is_some()
                                            && range.end <= value.source_sequence
                                    }
                                    None => range.end <= value.source_sequence,
                                }
                            });
                        if let Some(exact) = local_exact {
                            if exact.start != range.start
                                || exact.end != range.end
                                || exact.cas_ref != verified.receipt.cas_ref
                            {
                                return Err(IngestError::StoreCorrupt);
                            }
                            (Some(exact.digest), None)
                        } else if is_committed {
                            if state.exact.is_none() {
                                let watermark = state
                                    .committed_watermark
                                    .as_ref()
                                    .ok_or(IngestError::StoreCorrupt)?;
                                let exact = projected_exact_prefixes(
                                    prefix_projection
                                        .as_ref()
                                        .ok_or(IngestError::StoreCorrupt)?,
                                    &key.0,
                                    &key.1,
                                    state.origin_fence,
                                    watermark,
                                )?;
                                prefix_states
                                    .get_mut(&key)
                                    .ok_or(IngestError::StoreCorrupt)?
                                    .exact = Some(exact);
                            }
                            let exact = prefix_states
                                .get(&key)
                                .and_then(|state| state.exact.as_ref())
                                .and_then(|exact| exact.get(&range.end))
                                .ok_or(IngestError::StoreCorrupt)?;
                            if exact.start != range.start
                                || exact.end != range.end
                                || exact.cas_ref != verified.receipt.cas_ref
                            {
                                return Err(IngestError::StoreCorrupt);
                            }
                            (Some(exact.digest.clone()), None)
                        } else {
                            let state = prefix_states
                                .get_mut(&key)
                                .ok_or(IngestError::StoreCorrupt)?;
                            let next = state.advance(&verified.receipt)?;
                            (next.confirmed_prefix_digest.clone(), Some(next))
                        }
                    } else {
                        (None, None)
                    };
                let process_profile = verified.body.source_revision.as_str()
                    == evertrace_capture::process_source::SOURCE_REVISION
                    && evertrace_capture::process_source::is_native_profile(
                        verified.body.adapter_revision,
                        verified.body.parser_revision,
                    );
                let runtime_image = verified.body.source_revision.as_str()
                    == evertrace_capture::process_source::IMAGE_SOURCE_REVISION;
                let frozen_process = process_profile || runtime_image;
                let native_profile = process_profile
                    || (evertrace_capture::execution_source::is_source_revision(
                        verified.body.source_revision.as_str(),
                    ) && evertrace_capture::execution_source::is_qualified_revision(
                        verified.body.parser_revision,
                    ));
                // The journal validates the original whole command before
                // returning it. Preserve its first presentation across lost ack
                // and reload; verify every payload against this same frame/CAS.
                let committed_command = match replay_batch.get(&verified.body.command_id) {
                    Some(command) => Some(command.clone()),
                    None => self
                        .writer
                        .committed_command(verified.body.command_id)
                        .await
                        .map_err(map_writer_error)?,
                };
                let work_source = evertrace_capture::process_source::is_work_revision(
                    verified.body.source_revision.as_str(),
                );
                let committed_command = if committed_command.is_none() && work_source {
                    self.writer
                        .source_observation_command(verified.observation.source_observation_id)
                        .await
                        .map_err(map_writer_error)?
                } else {
                    committed_command
                };
                if let Some(committed_command) = committed_command {
                    let fresh_work_presentation =
                        work_source && committed_command.command_id != verified.body.command_id;
                    if native_profile || runtime_image {
                        if let Some(original) =
                            committed_command
                                .payloads
                                .iter()
                                .find_map(|payload| match payload {
                                    JournalPayload::SourceObservationRecorded(value)
                                        if value.source_observation_id
                                            == verified.observation.source_observation_id =>
                                    {
                                        Some(value.as_ref())
                                    }
                                    _ => None,
                                })
                        {
                            // Lost-ack replay preserves first admission, even after qualification or restart.
                            let mut weak = original.clone();
                            weak.correlation.admission =
                                evertrace_domain::evidence::CorrelationAdmission::Unavailable;
                            weak.correlation.strong_gate_receipt_ref = None;
                            if frozen_process {
                                weak.content_trust = verified.observation.content_trust;
                                weak.capture_completeness =
                                    verified.observation.capture_completeness;
                            }
                            if weak == verified.observation
                                && (frozen_process
                                    || evertrace_capture::execution_source::is_execution(
                                        original,
                                        &verified.receipt,
                                    ))
                            {
                                verified.observation.correlation = original.correlation.clone();
                                if frozen_process {
                                    verified.observation.content_trust = original.content_trust;
                                    verified.observation.capture_completeness =
                                        original.capture_completeness;
                                    verified.receipt.capture_completeness =
                                        original.capture_completeness;
                                    if let Some(surface) = &mut verified.surface {
                                        surface.content_trust = original.content_trust;
                                        surface.capture_completeness =
                                            original.capture_completeness;
                                    }
                                }
                            }
                        }
                    }
                    let receipt = committed_command
                        .payloads
                        .iter()
                        .find_map(|payload| match payload {
                            JournalPayload::SourceReceiptRecorded(receipt) => {
                                Some(receipt.as_ref())
                            }
                            _ => None,
                        })
                        .ok_or(IngestError::StoreCorrupt)?;
                    if fresh_work_presentation {
                        use evertrace_domain::evidence::EventTimeProvenance::RecordedAtFallback;
                        if verified.receipt.event_time_provenance != Some(RecordedAtFallback)
                            || receipt.event_time_provenance != Some(RecordedAtFallback)
                        {
                            return Err(IngestError::IdempotencyConflict);
                        }
                        // Re-observing one source event does not revise its first L0 clock.
                        verified.receipt.recorded_at_us = receipt.recorded_at_us;
                        verified.receipt.event_time_us = receipt.event_time_us;
                        if let Some(surface) = verified.surface.as_mut() {
                            surface.recorded_at_us = receipt.recorded_at_us;
                            surface.event_time_us = receipt.event_time_us;
                        }
                    }
                    verified
                        .receipt
                        .protected_presentation
                        .clone_from(&receipt.protected_presentation);
                    // Transport replay can relocate the same frame. Retain its first L0 receipt,
                    // not the retry segment's offset; all source/CAS/payload fields must still match.
                    verified
                        .receipt
                        .spool_byte_range
                        .clone_from(&receipt.spool_byte_range);
                    let original_algorithm = committed_command
                        .payloads
                        .iter()
                        .find_map(|payload| match payload {
                            JournalPayload::DirtyTarget(target) => {
                                Some(target.algorithm_revision.as_str())
                            }
                            _ => None,
                        })
                        .ok_or(IngestError::StoreCorrupt)?;
                    let original_watermark =
                        committed_command
                            .payloads
                            .iter()
                            .find_map(|payload| match payload {
                                JournalPayload::SourceIngestWatermark(watermark) => {
                                    Some(watermark.clone())
                                }
                                _ => None,
                            });
                    let expected = capture_event_drafts_with_watermark(
                        &verified,
                        digest,
                        effective_config_hash,
                        original_algorithm,
                        original_watermark,
                    )?
                    .into_iter()
                    .map(|event| event.payload)
                    .collect::<Vec<_>>();
                    if committed_command.payloads != expected {
                        return Err(IngestError::IdempotencyConflict);
                    }
                    committed += 1;
                    progress.committed_frames += 1;
                    progress.replayed_frames += 1;
                    progress.projected_surfaces += surface_count;
                    continue;
                }
                self.observe_live_process(&mut verified).await?;
                if native_profile {
                    if let Some(report) = self.execution_canary.as_ref().and_then(|canary| {
                        if process_profile {
                            canary.process_source_report()
                        } else {
                            canary.execution_source_report()
                        }
                    }) {
                        let correlation = &mut verified.observation.correlation;
                        if report.manifest().adapter_manifest_id
                            == verified.receipt.adapter_manifest_ref
                            && correlation.native_request_id.is_some()
                        {
                            let weak = correlation.clone();
                            correlation.admission =
                                evertrace_domain::evidence::CorrelationAdmission::ExactCapable;
                            correlation.strong_gate_receipt_ref =
                                Some(report.strong_normalization().protected_digest().into());
                            if correlation.validate().is_err() || correlation.exact_key().is_none()
                            {
                                *correlation = weak;
                            }
                        }
                    }
                }
                self.verify_namespace_support(&verified, &cas, &mut remaining)
                    .await?;
                if selected.is_none()
                    && verified.native_call.is_some()
                    && !matches!(&verified.body.source_local_evidence,
                        Some(evertrace_domain::evidence::SourceLocalEvidence::NativeCall(call)) if call.namespace_witness.is_some())
                {
                    if namespace_records.is_none() {
                        namespace_records = Some(
                            spool.read_durable_records(MAX_SEGMENTS_PER_DRAIN, 64 * 1024 * 1024),
                        );
                    }
                    match namespace_records.as_ref().ok_or(IngestError::Spool)? {
                        Ok(records) => {
                            self.freeze_namespace_probe(&verified, records, &cas, &mut remaining)?
                        }
                        Err(evertrace_capture::SpoolError::ResourceExhausted) => {
                            // Incomplete recovery cannot establish absence. Keep
                            // this observation weak rather than remeasure.
                        }
                        Err(error) => return Err(map_spool(*error)),
                    }
                }
                let command = JournalCommand::new(
                    verified.body.command_id,
                    capture_event_drafts_with_watermark(
                        &verified,
                        digest,
                        effective_config_hash,
                        &self.algorithm_revision,
                        watermark,
                    )?,
                )
                .map_err(|_| IngestError::InvalidRecord)?;
                let outcome = self
                    .writer
                    .commit(command, recorded_at_us)
                    .await
                    .map_err(map_writer_error)?;
                if !outcome.replayed {
                    // L0 is accepted first. A measured live directory gets one bounded
                    // physical pass; replay never probes a historical process/path.
                    self.normalize_live_native(&verified, &spool, recorded_at_us)
                        .await?;
                }
                committed += 1;
                progress.committed_frames += 1;
                progress.replayed_frames += usize::from(outcome.replayed);
                progress.projected_surfaces += surface_count;
            }
            if shutdown.is_some_and(|signal| *signal.borrow()) {
                return Ok(progress);
            }
            if committed != 0 {
                progress.synced_frontier = Some(
                    self.writer
                        .sync_frontier()
                        .await
                        .map_err(map_writer_error)?,
                );
            }
            if invalid {
                // No record is acknowledged or rewritten. Previously committed prefix commands stay canonical.
                spool.quarantine_segment(segment).map_err(map_spool)?;
                return Err(IngestError::Recovering);
            }
            let consumed = committed
                .checked_add(terminal.len())
                .ok_or(IngestError::InvalidRecord)?;
            if segment.complete() && (selected.is_none() || consumed == segment.frames().len()) {
                if !terminal.is_empty() {
                    terminal_segments.push((segment, consumed, terminal));
                } else {
                    spool
                        .acknowledge_segment(segment, consumed)
                        .map_err(map_spool_ack)?;
                    progress.sealed_segments += 1;
                }
            }
        }
        let terminal_count = terminal_segments.len();
        if terminal_count != 0 {
            self.discard_purged_segments(spool, terminal_segments)
                .await?;
            progress.sealed_segments = progress
                .sealed_segments
                .checked_add(terminal_count)
                .ok_or(IngestError::InvalidRecord)?;
        }
        Ok(progress)
    }

    async fn discard_purged_segments(
        &self,
        spool: &DurableSpool,
        terminal_segments: Vec<(SealedSegment, usize, Vec<CaptureRecordBody>)>,
    ) -> Result<(), IngestError> {
        let data_dir = self
            .snapshot
            .data_dir()
            .map_err(|_| IngestError::Snapshot)?;
        let fence = MaintenanceFence::open(data_dir).map_err(|_| IngestError::Cas)?;
        let guard = fence.exclusive().map_err(|_| IngestError::Cas)?;
        let snapshot = self.writer.project().await.map_err(map_writer_error)?;
        let purges = ScopePurgeCurrentView::from_snapshot(&snapshot)
            .map_err(|_| IngestError::StoreCorrupt)?
            .events
            .into_keys()
            .collect();
        if terminal_segments
            .iter()
            .flat_map(|(_, _, terminal)| terminal)
            .any(|body| !capture_is_purged(body, &purges))
        {
            return Err(IngestError::StoreCorrupt);
        }

        let candidates = terminal_segments
            .iter()
            .flat_map(|(_, _, terminal)| terminal)
            .map(|body| body.cas_ref.clone())
            .collect::<BTreeSet<_>>();
        let mut retained = snapshot
            .live_cas_refs_intersect(&candidates)
            .map_err(|_| IngestError::StoreCorrupt)?;
        let max_segments =
            usize::try_from(self.snapshot.max_main_files).map_err(|_| IngestError::Snapshot)?;
        for record in spool
            .read_durable_records(max_segments, self.snapshot.main_high_watermark_bytes)
            .map_err(|_| IngestError::Spool)?
        {
            let body = canonical_body(&record)?;
            if capture_is_purged(&body, &purges) {
                continue;
            }
            retained.extend(
                record
                    .cas_refs
                    .iter()
                    .filter(|reference| candidates.contains(*reference))
                    .cloned(),
            );
        }
        let digests = candidates
            .difference(&retained)
            .map(|reference| CasDigest::from_str(reference).map_err(|_| IngestError::Cas))
            .collect::<Result<Vec<_>, _>>()?;
        CasStore::delete_guarded_batch(&guard, &digests).map_err(|_| IngestError::Cas)?;
        for (segment, consumed, _) in terminal_segments {
            spool
                .acknowledge_segment(segment, consumed)
                .map_err(map_spool_ack)?;
        }
        Ok(())
    }
}

fn canonical_body(record: &SpoolRecord) -> Result<CaptureRecordBody, IngestError> {
    decode_validated_record_body(record)
        .map(|(body, _)| body)
        .map_err(|error| match error {
            evertrace_capture::SpoolFrameError::LegacyUnsupported => IngestError::LegacyRecord,
            evertrace_capture::SpoolFrameError::Corrupt => IngestError::IdentityMismatch,
            _ => IngestError::InvalidRecord,
        })
}

fn capture_is_purged(body: &CaptureRecordBody, purged: &BTreeSet<RepositoryId>) -> bool {
    body.repository_instance_id
        .is_some_and(|repository_id| purged.contains(&repository_id))
}

pub(crate) fn capture_event_drafts(
    verified: &crate::capture::VerifiedCapture,
    confirmed_prefix_digest: Option<String>,
    effective_config_hash: [u8; 32],
    algorithm_revision: &str,
) -> Result<Vec<JournalEventDraft>, IngestError> {
    capture_event_drafts_with_watermark(
        verified,
        confirmed_prefix_digest,
        effective_config_hash,
        algorithm_revision,
        None,
    )
}

fn capture_event_drafts_with_watermark(
    verified: &crate::capture::VerifiedCapture,
    confirmed_prefix_digest: Option<String>,
    effective_config_hash: [u8; 32],
    algorithm_revision: &str,
    watermark: Option<SourceIngestWatermark>,
) -> Result<Vec<JournalEventDraft>, IngestError> {
    let scope = EventScope {
        repository_id: verified
            .body
            .repository_instance_id
            .map(|value| value.to_string()),
        worktree_id: verified
            .body
            .worktree_instance_id
            .map(|value| value.to_string()),
        task_id: verified.body.task_id.map(|value| value.to_string()),
        session_id: Some(verified.body.source_session_ref.clone()),
        ..EventScope::default()
    };
    let source_kind = match verified.body.source_role {
        SourceRole::User | SourceRole::Assistant | SourceRole::Tool | SourceRole::Host => {
            SourceKind::Hook
        }
        SourceRole::Imported => SourceKind::Import,
    };
    let mut payloads = Vec::new();
    if verified.body.source_revision_mode == SourceRevisionMode::Replacement {
        payloads.push(JournalPayload::SourceRevisionRecorded(
            SourceRevisionRecorded {
                source_instance_id: verified.body.source_instance_id.clone(),
                source_revision: verified.body.source_revision.clone(),
                previous_source_revision: verified.body.previous_source_revision.clone(),
                mode: verified.body.source_revision_mode,
                recorded_at_us: verified.body.recorded_at_us,
            },
        ));
    }
    payloads.push(JournalPayload::SourceReceiptRecorded(Box::new(
        verified.receipt.clone(),
    )));
    payloads.push(JournalPayload::SourceObservationRecorded(Box::new(
        verified.observation.clone(),
    )));
    let watermark = watermark.unwrap_or(SourceIngestWatermark {
        source_instance_id: verified.body.source_instance_id.clone(),
        source_revision: verified.body.source_revision.clone(),
        source_sequence: verified.body.source_sequence,
        confirmed_prefix_digest,
        earlier_prefix: None,
    });
    if watermark.source_instance_id != verified.body.source_instance_id
        || watermark.source_revision != verified.body.source_revision
    {
        return Err(IngestError::InvalidRecord);
    }
    payloads.push(JournalPayload::SourceIngestWatermark(watermark));
    if let Some(surface) = verified.surface.clone() {
        payloads.push(JournalPayload::EvidenceSurfaceRecorded(Box::new(surface)));
    }
    payloads.push(JournalPayload::DirtyTarget(DirtyTarget {
        target_kind: DirtyTargetKind::EvidenceSurface,
        target_id: verified.observation.source_observation_id.to_string(),
        algorithm_revision: algorithm_revision.to_owned(),
        source_watermark: verified.body.source_sequence,
    }));
    payloads.push(JournalPayload::DirtyTarget(DirtyTarget {
        target_kind: DirtyTargetKind::PhysicalNormalization,
        target_id: verified.observation.source_observation_id.to_string(),
        algorithm_revision: algorithm_revision.to_owned(),
        source_watermark: verified.body.source_sequence,
    }));
    if verified.body.lifecycle.is_some() {
        payloads.push(JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::CaptureReconciliation,
            target_id: verified.observation.source_observation_id.to_string(),
            algorithm_revision: algorithm_revision.to_owned(),
            source_watermark: verified.body.source_sequence,
        }));
    }
    let events = payloads
        .into_iter()
        .map(|payload| JournalEventDraft {
            occurred_at_us: verified.body.event_time_us,
            source_kind,
            scope: scope.clone(),
            causation_id: None,
            correlation_id: None,
            effective_config_hash,
            algorithm_revision: algorithm_revision.to_owned(),
            payload,
        })
        .collect();
    Ok(events)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfirmedPrefixState {
    origin_fence: Option<u64>,
    committed_watermark: Option<SourceIngestWatermark>,
    exact: Option<BTreeMap<u64, ProjectedExactPrefix>>,
    local_exact: BTreeMap<u64, ProjectedExactPrefix>,
    local_end: u64,
    local_digest: Option<String>,
    prefix_end: u64,
    prefix_digest: Option<String>,
}

impl ConfirmedPrefixState {
    fn advance(
        &mut self,
        receipt: &evertrace_domain::evidence::SourceReceipt,
    ) -> Result<SourceIngestWatermark, IngestError> {
        let range = receipt
            .source_byte_range
            .as_ref()
            .ok_or(IngestError::InvalidRecord)?;
        if self
            .origin_fence
            .is_some_and(|fence| range.start < fence && range.end > fence)
        {
            return Err(IngestError::InvalidRecord);
        }
        let (end, previous) = if self.origin_fence.is_some_and(|fence| range.end <= fence) {
            (&mut self.prefix_end, &mut self.prefix_digest)
        } else {
            (&mut self.local_end, &mut self.local_digest)
        };
        if range.start != *end {
            return Err(IngestError::InvalidRecord);
        }
        let digest = confirmed_prefix_digest(
            receipt.source_instance_id.as_str(),
            receipt.source_revision.as_str(),
            range.start,
            range.end,
            previous.clone(),
            &receipt.cas_ref,
        )?;
        *end = range.end;
        *previous = Some(digest.clone());
        self.local_exact.insert(
            range.end,
            ProjectedExactPrefix {
                start: range.start,
                end: range.end,
                cas_ref: receipt.cas_ref.clone(),
                digest,
            },
        );
        Ok(SourceIngestWatermark {
            source_instance_id: receipt.source_instance_id.clone(),
            source_revision: receipt.source_revision.clone(),
            source_sequence: self.local_end,
            confirmed_prefix_digest: self.local_digest.clone(),
            earlier_prefix: self
                .origin_fence
                .map(|fence_byte| SourceImportEarlierPrefix {
                    fence_byte,
                    through_byte: self.prefix_end,
                    digest: self.prefix_digest.clone(),
                }),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectedExactPrefix {
    start: u64,
    end: u64,
    cas_ref: String,
    digest: String,
}

fn projected_confirmed_prefix(
    snapshot: &ProjectionSnapshot,
    source_instance: &SourceInstanceId,
    source_revision: &SourceRevision,
    origin_fence: Option<u64>,
) -> Result<ConfirmedPrefixState, IngestError> {
    let key = SourceIngestWatermark {
        source_instance_id: source_instance.clone(),
        source_revision: source_revision.clone(),
        source_sequence: 0,
        confirmed_prefix_digest: None,
        earlier_prefix: None,
    }
    .stable_key();
    let Some(row) = snapshot.row(&format!("runtime:watermark:source:{key}")) else {
        return Ok(ConfirmedPrefixState {
            origin_fence,
            committed_watermark: None,
            exact: None,
            local_exact: BTreeMap::new(),
            local_end: origin_fence.unwrap_or(0),
            local_digest: None,
            prefix_end: 0,
            prefix_digest: None,
        });
    };
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(IngestError::StoreCorrupt)?,
    )
    .map_err(|_| IngestError::StoreCorrupt)?;
    let JournalPayload::SourceIngestWatermark(watermark) = payload else {
        return Err(IngestError::StoreCorrupt);
    };
    if &watermark.source_instance_id != source_instance
        || &watermark.source_revision != source_revision
    {
        return Err(IngestError::StoreCorrupt);
    }
    // A persisted fence describes admitted history even after its live origin
    // closes or metadata advances to another revision. It grants no new reads.
    let origin_fence = match (&watermark.earlier_prefix, origin_fence) {
        (Some(prefix), Some(fence)) if prefix.fence_byte != fence => {
            return Err(IngestError::StoreCorrupt);
        }
        (Some(prefix), _) => Some(prefix.fence_byte),
        (None, value) => value,
    };
    let (local_end, local_digest, prefix_end, prefix_digest) = match origin_fence {
        Some(fence) => {
            let prefix = watermark
                .earlier_prefix
                .as_ref()
                .filter(|prefix| prefix.fence_byte == fence)
                .ok_or(IngestError::StoreCorrupt)?;
            let suffix_end = if watermark.confirmed_prefix_digest.is_some() {
                if watermark.source_sequence <= fence {
                    return Err(IngestError::StoreCorrupt);
                }
                watermark.source_sequence
            } else {
                if watermark.source_sequence != fence {
                    return Err(IngestError::StoreCorrupt);
                }
                fence
            };
            (
                suffix_end,
                watermark.confirmed_prefix_digest.clone(),
                prefix.through_byte,
                prefix.digest.clone(),
            )
        }
        None => {
            if watermark.earlier_prefix.is_some() || watermark.confirmed_prefix_digest.is_none() {
                return Err(IngestError::StoreCorrupt);
            }
            (
                watermark.source_sequence,
                watermark.confirmed_prefix_digest.clone(),
                0,
                None,
            )
        }
    };
    Ok(ConfirmedPrefixState {
        origin_fence,
        committed_watermark: Some(watermark),
        exact: None,
        local_exact: BTreeMap::new(),
        local_end,
        local_digest,
        prefix_end,
        prefix_digest,
    })
}

fn projected_exact_prefixes(
    snapshot: &ProjectionSnapshot,
    source_instance: &str,
    source_revision: &str,
    origin_fence: Option<u64>,
    watermark: &SourceIngestWatermark,
) -> Result<BTreeMap<u64, ProjectedExactPrefix>, IngestError> {
    let mut receipts = Vec::new();
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_receipt"))
    {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(IngestError::StoreCorrupt)?,
        )
        .map_err(|_| IngestError::StoreCorrupt)?;
        let JournalPayload::SourceReceiptRecorded(receipt) = payload else {
            return Err(IngestError::StoreCorrupt);
        };
        if receipt.source_instance_id.as_str() != source_instance
            || receipt.source_revision.as_str() != source_revision
        {
            continue;
        }
        let range = receipt
            .source_byte_range
            .as_ref()
            .ok_or(IngestError::StoreCorrupt)?;
        if range.end != receipt.source_sequence || range.end <= range.start {
            return Err(IngestError::StoreCorrupt);
        }
        receipts.push((range.start, range.end, receipt.cas_ref.clone()));
    }
    if receipts.is_empty() {
        return Err(IngestError::StoreCorrupt);
    }
    receipts.sort_by_key(|(start, end, _)| (*end, *start));
    let mut prefix_cursor = 0_u64;
    let mut prefix_digest = None;
    let mut main_cursor = origin_fence.unwrap_or(0);
    let mut main_digest = None;
    let mut exact = BTreeMap::new();
    for (start, end, cas_ref) in receipts {
        let (cursor, previous) = match origin_fence {
            Some(fence) if end <= fence => (&mut prefix_cursor, &mut prefix_digest),
            Some(fence) if start >= fence => (&mut main_cursor, &mut main_digest),
            Some(_) => return Err(IngestError::StoreCorrupt),
            None if end <= watermark.source_sequence => (&mut main_cursor, &mut main_digest),
            None => return Err(IngestError::StoreCorrupt),
        };
        if start != *cursor {
            return Err(IngestError::StoreCorrupt);
        }
        let digest = confirmed_prefix_digest(
            source_instance,
            source_revision,
            start,
            end,
            previous.clone(),
            &cas_ref,
        )?;
        *cursor = end;
        *previous = Some(digest.clone());
        if exact
            .insert(
                end,
                ProjectedExactPrefix {
                    start,
                    end,
                    cas_ref,
                    digest: digest.clone(),
                },
            )
            .is_some()
        {
            return Err(IngestError::StoreCorrupt);
        }
    }
    match origin_fence {
        Some(fence) => {
            let prefix = watermark
                .earlier_prefix
                .as_ref()
                .filter(|prefix| prefix.fence_byte == fence)
                .ok_or(IngestError::StoreCorrupt)?;
            let suffix_end = if watermark.confirmed_prefix_digest.is_some() {
                watermark.source_sequence
            } else {
                fence
            };
            if prefix_cursor != prefix.through_byte
                || prefix_digest != prefix.digest
                || main_cursor != suffix_end
                || main_digest != watermark.confirmed_prefix_digest
            {
                return Err(IngestError::StoreCorrupt);
            }
        }
        None => {
            if main_cursor != watermark.source_sequence
                || main_digest != watermark.confirmed_prefix_digest
            {
                return Err(IngestError::StoreCorrupt);
            }
        }
    }
    Ok(exact)
}

pub(crate) fn confirmed_prefix_digest(
    source_instance: &str,
    source_revision: &str,
    start: u64,
    end: u64,
    previous: Option<String>,
    cas_ref: &str,
) -> Result<String, IngestError> {
    let digest = sha256(
        CONFIRMED_PREFIX_TAG,
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(source_instance.to_owned()),
            CanonicalValue::String(source_revision.to_owned()),
            CanonicalValue::Integer(i128::from(start)),
            CanonicalValue::Integer(i128::from(end)),
            previous.map_or(CanonicalValue::Null, CanonicalValue::String),
            CanonicalValue::String(cas_ref.to_owned()),
        ]),
    )
    .map_err(|_| IngestError::InvalidRecord)?;
    Ok(hex(&digest))
}

// Reuse the sealed observation's existing canonical digest as UUIDv7 entropy.
// The timestamp is its actual recorded time; no second digest or registry is stored.
fn source_snapshot_command_id(
    id: SourceObservationId,
    recorded_at_us: i64,
) -> Result<CommandId, IngestError> {
    let timestamp = u64::try_from(recorded_at_us / 1000).map_err(|_| IngestError::InvalidRecord)?;
    let identity = id.to_string();
    let digest = identity
        .strip_prefix("obs:")
        .ok_or(IngestError::InvalidRecord)?;
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&timestamp.to_be_bytes()[2..]);
    for (index, byte) in bytes[6..].iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| IngestError::InvalidRecord)?;
    }
    bytes[6] = bytes[6] & 0x0f | 0x70;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    bytes[15] ^= 0x53;
    let value = bytes.map(|byte| format!("{byte:02x}")).concat();
    format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    )
    .parse()
    .map_err(|_| IngestError::InvalidRecord)
}

fn map_writer_error(error: WriterActorError) -> IngestError {
    match error {
        WriterActorError::IdempotencyConflict => IngestError::IdempotencyConflict,
        WriterActorError::StoreCorrupt => IngestError::StoreCorrupt,
        error => {
            tracing::warn!(target: "evertrace_lifecycle", ?error, "capture writer operation failed");
            IngestError::Store
        }
    }
}

fn map_spool(error: evertrace_capture::SpoolError) -> IngestError {
    if error == evertrace_capture::SpoolError::Busy {
        IngestError::Busy
    } else if error == evertrace_capture::SpoolError::RecoveryRequired {
        IngestError::Recovering
    } else {
        IngestError::Spool
    }
}

fn map_spool_ack(error: evertrace_capture::SpoolError) -> IngestError {
    if error == evertrace_capture::SpoolError::Busy {
        IngestError::Busy
    } else {
        IngestError::Acknowledgement
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IngestError {
    #[error("capture spool is busy")]
    Busy,
    #[error("capture runtime snapshot is invalid")]
    Snapshot,
    #[error("capture spool is unavailable")]
    Spool,
    #[error("capture spool requires recovery")]
    Recovering,
    #[error("capture record uses an unsupported legacy format")]
    LegacyRecord,
    #[error("capture record is invalid")]
    InvalidRecord,
    #[error("capture record identity does not match its source tuple")]
    IdentityMismatch,
    #[error("capture CAS is unavailable")]
    Cas,
    #[error("capture CAS metadata does not match the record")]
    CasMismatch,
    #[error("evidence journal command conflicts with an existing command")]
    IdempotencyConflict,
    #[error("evidence store is corrupt")]
    StoreCorrupt,
    #[error("evidence store operation failed")]
    Store,
    #[error("sealed segment acknowledgement failed")]
    Acknowledgement,
}
