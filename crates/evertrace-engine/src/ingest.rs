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
    evidence::{SourceInstanceId, SourceRevision, SourceRevisionMode, SourceRole},
    ids::SourceObservationId,
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, EventScope, JournalCommand, JournalEventDraft, JournalPayload,
    ProjectionSnapshot, ScopePurgeCurrentView, SourceIngestWatermark, SourceKind,
    SourceRevisionRecorded,
};
use thiserror::Error;

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
}

#[derive(Clone)]
pub struct EvidenceIngestor {
    snapshot: RuntimeSnapshot,
    writer: WriterHandle,
    effective_config_hash: [u8; 32],
    algorithm_revision: String,
    config: Option<std::sync::Arc<crate::ConfigReloadService>>,
    operation_config: Option<std::sync::Arc<evertrace_domain::config::EffectiveConfig>>,
    recovery_wakeup: Option<tokio::sync::watch::Sender<u64>>,
}

impl EvidenceIngestor {
    pub fn with_recovery_wakeup(mut self, wakeup: tokio::sync::watch::Sender<u64>) -> Self {
        self.recovery_wakeup = Some(wakeup);
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
            let result = self.drain_page(&mut cursor).await;
            drop(guard);
            match result {
                Ok(_) => recovering = false,
                Err(IngestError::Busy) => {}
                Err(IngestError::Recovering) => {
                    if !recovering && let Some(wakeup) = &self.recovery_wakeup {
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
        let result = self.drain_segments(&spool, segments, None, true).await?;
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
            recovery_wakeup: None,
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
        self.drain_segments(&spool, segments, selected, false).await
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

    async fn drain_segments(
        &self,
        spool: &DurableSpool,
        segments: Vec<SealedSegment>,
        selected: Option<&BTreeSet<String>>,
        bounded: bool,
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
            let purge_snapshot = self.writer.project().await.map_err(map_writer_error)?;
            let purge_view = ScopePurgeCurrentView::from_snapshot(&purge_snapshot)
                .map_err(|_| IngestError::StoreCorrupt)?;
            let mut committed = 0_usize;
            let mut terminal = Vec::new();
            let mut shared_maintenance = None;
            for frame in segment.frames() {
                if selected.is_some_and(|ids| !ids.contains(&frame.record.source_observation_id)) {
                    continue;
                }
                let body = canonical_body(&frame.record)?;
                if capture_is_purged(&body, &purge_view) {
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
                let mut verified = verify_capture_frame_presented(
                    frame,
                    &cas,
                    &mut remaining,
                    config.as_ref().map(|config| &config.config().capture),
                )?;
                let surface_count = usize::from(verified.surface.is_some());
                let recorded_at_us = verified.body.recorded_at_us;
                let digest = if evertrace_store::session_import::is_session_import_source(
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
                            prefix_projection =
                                Some(self.writer.project().await.map_err(map_writer_error)?);
                        }
                        let projected = projected_confirmed_prefix(
                            prefix_projection
                                .as_ref()
                                .ok_or(IngestError::StoreCorrupt)?,
                            &verified.body.source_instance_id,
                            &verified.body.source_revision,
                        )?;
                        prefix_states.insert(key.clone(), projected);
                    }
                    let state = prefix_states.get(&key).ok_or(IngestError::StoreCorrupt)?;
                    if verified.body.source_sequence <= state.committed_end {
                        if state.exact.is_none() {
                            let exact = projected_exact_prefixes(
                                prefix_projection
                                    .as_ref()
                                    .ok_or(IngestError::StoreCorrupt)?,
                                &key.0,
                                &key.1,
                                state.committed_end,
                                state.committed_digest.as_deref(),
                            )?;
                            prefix_states
                                .get_mut(&key)
                                .ok_or(IngestError::StoreCorrupt)?
                                .exact = Some(exact);
                        }
                        let exact = prefix_states
                            .get(&key)
                            .and_then(|state| state.exact.as_ref())
                            .and_then(|exact| exact.get(&verified.body.source_sequence))
                            .ok_or(IngestError::StoreCorrupt)?;
                        if exact.start != range.start
                            || exact.end != range.end
                            || exact.cas_ref != verified.receipt.cas_ref
                        {
                            return Err(IngestError::StoreCorrupt);
                        }
                        Some(exact.digest.clone())
                    } else {
                        if range.start != state.local_end {
                            return Err(IngestError::InvalidRecord);
                        }
                        let digest = confirmed_prefix_digest(
                            &key.0,
                            &key.1,
                            range.start,
                            range.end,
                            state.local_digest.as_deref(),
                            &verified.receipt.cas_ref,
                        )?;
                        let state = prefix_states
                            .get_mut(&key)
                            .ok_or(IngestError::StoreCorrupt)?;
                        state.local_end = range.end;
                        state.local_digest = Some(digest.clone());
                        Some(digest)
                    }
                } else {
                    None
                };
                // The journal validates the original whole command before
                // returning it. Preserve its first presentation across lost ack
                // and reload; verify every payload against this same frame/CAS.
                if let Some(committed_command) = self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(map_writer_error)?
                {
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
                    verified
                        .receipt
                        .protected_presentation
                        .clone_from(&receipt.protected_presentation);
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
                    let expected = capture_event_drafts(
                        &verified,
                        digest,
                        effective_config_hash,
                        original_algorithm,
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
                    capture_event_drafts(
                        &verified,
                        digest,
                        effective_config_hash,
                        &self.algorithm_revision,
                    )?,
                )
                .map_err(|_| IngestError::InvalidRecord)?;
                let outcome = self
                    .writer
                    .commit(command, recorded_at_us)
                    .await
                    .map_err(map_writer_error)?;
                committed += 1;
                progress.committed_frames += 1;
                progress.replayed_frames += usize::from(outcome.replayed);
                progress.projected_surfaces += surface_count;
            }
            if committed != 0 {
                self.writer.project().await.map_err(map_writer_error)?;
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
            .map_err(|_| IngestError::StoreCorrupt)?;
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

fn capture_is_purged(body: &CaptureRecordBody, purges: &ScopePurgeCurrentView) -> bool {
    body.repository_instance_id
        .is_some_and(|repository_id| purges.events.contains_key(&repository_id))
}

pub(crate) fn capture_event_drafts(
    verified: &crate::capture::VerifiedCapture,
    confirmed_prefix_digest: Option<String>,
    effective_config_hash: [u8; 32],
    algorithm_revision: &str,
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
    payloads.push(JournalPayload::SourceIngestWatermark(
        SourceIngestWatermark {
            source_instance_id: verified.body.source_instance_id.clone(),
            source_revision: verified.body.source_revision.clone(),
            source_sequence: verified.body.source_sequence,
            confirmed_prefix_digest,
        },
    ));
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
    committed_end: u64,
    committed_digest: Option<String>,
    exact: Option<BTreeMap<u64, ProjectedExactPrefix>>,
    local_end: u64,
    local_digest: Option<String>,
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
) -> Result<ConfirmedPrefixState, IngestError> {
    let key = SourceIngestWatermark {
        source_instance_id: source_instance.clone(),
        source_revision: source_revision.clone(),
        source_sequence: 0,
        confirmed_prefix_digest: None,
    }
    .stable_key();
    let Some(row) = snapshot.row(&format!("runtime:watermark:source:{key}")) else {
        return Ok(ConfirmedPrefixState {
            committed_end: 0,
            committed_digest: None,
            exact: None,
            local_end: 0,
            local_digest: None,
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
        || watermark.source_sequence == 0
    {
        return Err(IngestError::StoreCorrupt);
    }
    let digest = watermark
        .confirmed_prefix_digest
        .clone()
        .ok_or(IngestError::StoreCorrupt)?;
    Ok(ConfirmedPrefixState {
        committed_end: watermark.source_sequence,
        committed_digest: Some(digest.clone()),
        exact: None,
        local_end: watermark.source_sequence,
        local_digest: Some(digest),
    })
}

fn projected_exact_prefixes(
    snapshot: &ProjectionSnapshot,
    source_instance: &str,
    source_revision: &str,
    committed_end: u64,
    expected: Option<&str>,
) -> Result<BTreeMap<u64, ProjectedExactPrefix>, IngestError> {
    let expected = expected.ok_or(IngestError::StoreCorrupt)?;
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
    let mut cursor = 0_u64;
    let mut digest = None;
    let mut exact = BTreeMap::new();
    for (start, end, cas_ref) in receipts {
        if start != cursor || end > committed_end {
            return Err(IngestError::StoreCorrupt);
        }
        let next_digest = confirmed_prefix_digest(
            source_instance,
            source_revision,
            start,
            end,
            digest.as_deref(),
            &cas_ref,
        )?;
        if exact
            .insert(
                end,
                ProjectedExactPrefix {
                    start,
                    end,
                    cas_ref,
                    digest: next_digest.clone(),
                },
            )
            .is_some()
        {
            return Err(IngestError::StoreCorrupt);
        }
        digest = Some(next_digest);
        cursor = end;
    }
    if cursor != committed_end || digest.as_deref() != Some(expected) {
        return Err(IngestError::StoreCorrupt);
    }
    Ok(exact)
}

fn confirmed_prefix_digest(
    source_instance: &str,
    source_revision: &str,
    start: u64,
    end: u64,
    previous: Option<&str>,
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
            previous.map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_owned())
            }),
            CanonicalValue::String(cas_ref.to_owned()),
        ]),
    )
    .map_err(|_| IngestError::InvalidRecord)?;
    Ok(hex_digest(&digest))
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn map_writer_error(error: WriterActorError) -> IngestError {
    match error {
        WriterActorError::IdempotencyConflict => IngestError::IdempotencyConflict,
        WriterActorError::StoreCorrupt => IngestError::StoreCorrupt,
        _ => IngestError::Store,
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
