//! Exact semantic content ranges. No CAS locator, writer effect or Web cache.
use crate::service::actions;
use evertrace_domain::query::{
    HUMAN_CONTENT_LIMIT, HumanContentCursor, HumanContentRepresentation,
};
use evertrace_store::JournalPayload;

use super::{
    HumanContentState, HumanGovernanceError, HumanGovernanceService, HumanSemanticContent, export,
    presentation,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanContentChunk {
    pub frontier: u64,
    pub object_ref: String,
    pub revision_ref: String,
    pub representation: HumanContentRepresentation,
    pub state: HumanContentState,
    pub total_bytes: Option<u64>,
    pub range_start: Option<u64>,
    pub range_end: Option<u64>,
    pub text: Option<String>,
    pub previous_cursor: Option<String>,
    pub next_cursor: Option<String>,
}

impl HumanGovernanceService {
    async fn source_text(
        &self,
        snapshot: &evertrace_store::projections::ProjectionSnapshot,
        row: &evertrace_store::objects::ObjectRow,
    ) -> Result<String, HumanContentState> {
        use evertrace_domain::evidence::ProtectedPresentation;
        let decode = |row: &evertrace_store::objects::ObjectRow| {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanContentState::Unavailable)?,
            )
            .map_err(|_| HumanContentState::Unavailable)?;
            payload
                .validate()
                .map_err(|_| HumanContentState::Unavailable)?;
            Ok::<_, HumanContentState>(payload)
        };
        // Keep the selected exact observation, rather than replacing it with
        // another observation reached through a possibly inconsistent receipt.
        let (receipt, observation) = match decode(row)? {
            JournalPayload::SourceReceiptRecorded(value) => {
                let observation = snapshot
                    .row(&format!(
                        "object:evidence:source_observation:{}",
                        value.source_observation_id
                    ))
                    .ok_or(HumanContentState::Unavailable)?;
                let JournalPayload::SourceObservationRecorded(observation) = decode(observation)?
                else {
                    return Err(HumanContentState::Unavailable);
                };
                (value, observation)
            }
            JournalPayload::SourceObservationRecorded(value) => {
                let receipt = snapshot
                    .row(&format!(
                        "object:evidence:source_receipt:{}",
                        value.source_receipt_ref
                    ))
                    .ok_or(HumanContentState::Unavailable)?;
                let JournalPayload::SourceReceiptRecorded(receipt) = decode(receipt)? else {
                    return Err(HumanContentState::Unavailable);
                };
                (receipt, value)
            }
            _ => return Err(HumanContentState::Unsupported),
        };
        if matches!(
            receipt.protected_presentation,
            Some(ProtectedPresentation::Unavailable { .. })
        ) {
            return Err(HumanContentState::Unsupported);
        }
        let cas_dir = self
            .runtime_snapshot
            .as_ref()
            .ok_or(HumanContentState::Unavailable)?
            .cas_dir
            .clone();
        let deadline = std::time::Instant::now() + presentation::READ_DEADLINE;
        // Verify the entire archive under the actual reader fence. Cancellation
        // covers encoded reads, decompression and hashing, not just the reply.
        // This still retains the archive; it is not a constant-RSS range reader.
        self.writer
            .read_handle()
            .read_blocking(move |cancel| {
                let check = || {
                    cancel.check()?;
                    export::check_deadline(deadline).map_err(|_| evertrace_store::StoreError::Io)
                };
                check()?;
                let cas = evertrace_capture::CasStore::open_existing(cas_dir)
                    .map_err(|_| evertrace_store::StoreError::Io)?;
                let digest = evertrace_capture::CasStore::parse_digest(&receipt.cas_ref)
                    .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?;
                let (bytes, _) = cas
                    .read_bounded_checked(
                        &digest,
                        export::MAX_ENCODED_BYTES,
                        export::MAX_DECODED_BYTES,
                        || check().map_err(|_| evertrace_capture::CasError::ReadCancelled),
                    )
                    .map_err(|_| evertrace_store::StoreError::Io)?;
                check()?;
                export::validate_source_archive(&receipt, &observation, &bytes)
                    .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?;
                check()?;
                let text = match String::from_utf8(bytes) {
                    Ok(text) if !text.contains('\0') => Ok(text),
                    _ => Err(HumanContentState::Unsupported),
                };
                check()?;
                Ok(text)
            })
            .await
            .map_err(|_| HumanContentState::Unavailable)?
    }

    pub async fn content(
        &self,
        object_ref: &str,
        revision_ref: &str,
        expected_frontier: u64,
        representation: HumanContentRepresentation,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<HumanContentChunk, u64>, HumanGovernanceError> {
        if !super::valid_ref(object_ref)
            || object_ref.len() > 512
            || !super::valid_ref(revision_ref)
            || revision_ref.len() > 512
            || !(4..=HUMAN_CONTENT_LIMIT).contains(&limit)
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let cursor = after
            .map(|value| {
                if value.len() > 2048 {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                let cursor: HumanContentCursor =
                    serde_json::from_str(value).map_err(|_| HumanGovernanceError::InvalidInput)?;
                cursor
                    .validate_for(object_ref, revision_ref, representation)
                    .map_err(|_| HumanGovernanceError::InvalidInput)?;
                Ok(cursor)
            })
            .transpose()?;
        // Reuse the canonical exact-detail snapshot and access closure. This is
        // request-local; response ranges do not claim an optimized point-read
        // metadata implementation or introduce a second permission index.
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier < expected_frontier {
            return Ok(Err(snapshot.frontier));
        }
        let mut result = HumanContentChunk {
            frontier: snapshot.frontier,
            object_ref: object_ref.into(),
            revision_ref: revision_ref.into(),
            representation,
            state: HumanContentState::Missing,
            total_bytes: None,
            range_start: None,
            range_end: None,
            text: None,
            previous_cursor: None,
            next_cursor: None,
        };
        let selected = actions::select_object_row(&snapshot, revision_ref)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let Some((row, _)) = selected else {
            return Ok(Ok(result));
        };
        if row.current_revision_id.as_deref() != Some(revision_ref)
            || !(row.row_id == object_ref
                || row.object_id.as_deref() == Some(object_ref)
                || object_ref == revision_ref)
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        if !matches!(
            row.object_kind.as_deref(),
            Some(
                "atom_revision"
                    | "procedure_revision"
                    | "core_membership"
                    | "semantic_digest"
                    | "revision_proposal_revision"
                    | "source_receipt"
                    | "source_observation"
                    | "work_episode"
                    | "attempt"
                    | "operation_burst"
                    | "operation"
                    | "capture_receipt"
                    | "capture_receipt_revision"
            )
        ) {
            result.state = HumanContentState::Unsupported;
            return Ok(Ok(result));
        }
        if let Err(error) = self
            .readable_row(
                &snapshot,
                row,
                std::time::Instant::now() + presentation::READ_DEADLINE,
            )
            .await
        {
            result.state = presentation::access_state(error);
            return Ok(Ok(result));
        }
        // Source text is the complete native-verified protected archive, never
        // a stored preview, an EvidenceSurface or a Python-supplied CAS path.
        let text = if matches!(
            row.object_kind.as_deref(),
            Some("source_receipt" | "source_observation")
        ) {
            if representation != HumanContentRepresentation::SourceText {
                result.state = HumanContentState::Unsupported;
                return Ok(Ok(result));
            }
            match self.source_text(&snapshot, row).await {
                Ok(text) => text,
                Err(state) => {
                    result.state = state;
                    return Ok(Ok(result));
                }
            }
        } else if row.object_kind.as_deref() == Some("work_episode")
            && representation == HumanContentRepresentation::Text
        {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let JournalPayload::WorkEpisodeRecorded(value) = payload else {
                return Err(HumanGovernanceError::Store);
            };
            let mut text = value.phase_contract.local_goal;
            text.push_str("\n\n未解决事项\n");
            for (index, entry) in value.open_loops.iter().enumerate() {
                use std::fmt::Write;
                writeln!(text, "{}. {}", index + 1, entry)
                    .map_err(|_| HumanGovernanceError::Store)?;
            }
            text
        } else if row.object_kind.as_deref() == Some("revision_proposal_revision") {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let JournalPayload::RevisionProposalRecorded(value) = payload else {
                return Err(HumanGovernanceError::Store);
            };
            if representation != HumanContentRepresentation::SemanticJson {
                result.state = HumanContentState::Unsupported;
                return Ok(Ok(result));
            }
            serde_json::to_string_pretty(&value).map_err(|_| HumanGovernanceError::Store)?
        } else {
            let Some((content, _)) = presentation::semantic_value(row)? else {
                result.state = HumanContentState::Unsupported;
                return Ok(Ok(result));
            };
            match (&content, representation) {
                (HumanSemanticContent::Atom(value), HumanContentRepresentation::Text) => {
                    value.value.text.clone()
                }
                (_, HumanContentRepresentation::SemanticJson) => {
                    serde_json::to_string_pretty(&content)
                        .map_err(|_| HumanGovernanceError::Store)?
                }
                _ => {
                    result.state = HumanContentState::Unsupported;
                    return Ok(Ok(result));
                }
            }
        };
        let offset = cursor.as_ref().map_or(0, |cursor| cursor.offset);
        let offset = usize::try_from(offset).map_err(|_| HumanGovernanceError::InvalidInput)?;
        if offset > text.len() || !text.is_char_boundary(offset) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let (mut start, mut end) = if cursor.as_ref().is_some_and(|cursor| cursor.backwards) {
            (offset.saturating_sub(usize::from(limit)), offset)
        } else {
            (
                offset,
                offset.saturating_add(usize::from(limit)).min(text.len()),
            )
        };
        while !text.is_char_boundary(start) {
            start += 1;
        }
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let encode_cursor = |offset, backwards| {
            serde_json::to_string(&HumanContentCursor {
                object_ref: object_ref.into(),
                revision_ref: revision_ref.into(),
                representation,
                offset,
                backwards,
            })
            .map_err(|_| HumanGovernanceError::Store)
        };
        result.state = HumanContentState::Ready;
        result.total_bytes = Some(text.len() as u64);
        result.range_start = Some(start as u64);
        result.range_end = Some(end as u64);
        result.text = Some(text[start..end].into());
        result.previous_cursor = (start > 0)
            .then(|| encode_cursor(start as u64, true))
            .transpose()?;
        result.next_cursor = (end < text.len())
            .then(|| encode_cursor(end as u64, false))
            .transpose()?;
        Ok(Ok(result))
    }
}
