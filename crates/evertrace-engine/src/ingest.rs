use evertrace_capture::{CasStore, DurableSpool, RuntimeSnapshot};
use evertrace_domain::evidence::{SourceRevisionMode, SourceRole};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, EventScope, JournalCommand, JournalEventDraft, JournalPayload,
    SourceIngestWatermark, SourceKind, SourceRevisionRecorded,
};
use thiserror::Error;

use crate::{WriterActorError, WriterHandle, capture::verify_capture_frame};

const MAX_SEGMENTS_PER_DRAIN: usize = 16;

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
}

impl EvidenceIngestor {
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
        })
    }

    pub async fn drain_once(&self) -> Result<DrainProgress, IngestError> {
        let cas = CasStore::open(self.snapshot.cas_dir.clone()).map_err(|_| IngestError::Cas)?;
        let (mut spool, recovery) = DurableSpool::open(
            self.snapshot.spool_dir.clone(),
            self.snapshot
                .spool_limits()
                .map_err(|_| IngestError::Snapshot)?,
        )
        .map_err(|_| IngestError::Spool)?;
        if recovery.repaired_tail_bytes != 0 || !recovery.gaps.is_empty() {
            return Err(IngestError::Recovering);
        }
        spool
            .seal_active(self.snapshot.generation)
            .map_err(|_| IngestError::Spool)?;
        let segments = spool
            .sealed_segments(MAX_SEGMENTS_PER_DRAIN)
            .map_err(|_| IngestError::Spool)?;
        let mut progress = DrainProgress::default();
        for segment in segments {
            let mut committed = 0_usize;
            for frame in segment.frames() {
                let verified = verify_capture_frame(frame, &cas)?;
                let surface_count = usize::from(verified.surface.is_some());
                let recorded_at_us = verified.body.recorded_at_us;
                let command = self.command_for(verified)?;
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
            self.writer.project().await.map_err(map_writer_error)?;
            spool
                .acknowledge_segment(segment, committed)
                .map_err(|_| IngestError::Acknowledgement)?;
            progress.sealed_segments += 1;
        }
        Ok(progress)
    }

    fn command_for(
        &self,
        verified: crate::capture::VerifiedCapture,
    ) -> Result<JournalCommand, IngestError> {
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
            verified.receipt,
        )));
        payloads.push(JournalPayload::SourceObservationRecorded(Box::new(
            verified.observation.clone(),
        )));
        payloads.push(JournalPayload::SourceIngestWatermark(
            SourceIngestWatermark {
                source_instance_id: verified.body.source_instance_id.clone(),
                source_revision: verified.body.source_revision.clone(),
                source_sequence: verified.body.source_sequence,
            },
        ));
        if let Some(surface) = verified.surface {
            payloads.push(JournalPayload::EvidenceSurfaceRecorded(Box::new(surface)));
        }
        payloads.push(JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::EvidenceSurface,
            target_id: verified.observation.source_observation_id.to_string(),
            algorithm_revision: self.algorithm_revision.clone(),
            source_watermark: verified.body.source_sequence,
        }));
        payloads.push(JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: verified.observation.source_observation_id.to_string(),
            algorithm_revision: self.algorithm_revision.clone(),
            source_watermark: verified.body.source_sequence,
        }));
        if verified.body.lifecycle.is_some() {
            payloads.push(JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::CaptureReconciliation,
                target_id: verified.observation.source_observation_id.to_string(),
                algorithm_revision: self.algorithm_revision.clone(),
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
                effective_config_hash: self.effective_config_hash,
                algorithm_revision: self.algorithm_revision.clone(),
                payload,
            })
            .collect();
        JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| IngestError::InvalidRecord)
    }
}

fn map_writer_error(error: WriterActorError) -> IngestError {
    match error {
        WriterActorError::IdempotencyConflict => IngestError::IdempotencyConflict,
        WriterActorError::StoreCorrupt => IngestError::StoreCorrupt,
        _ => IngestError::Store,
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IngestError {
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
