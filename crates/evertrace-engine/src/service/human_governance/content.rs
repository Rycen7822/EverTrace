//! Exact semantic content ranges. No CAS locator, writer effect or Web cache.
use crate::service::actions;
use evertrace_domain::query::{
    HUMAN_CONTENT_LIMIT, HumanContentCursor, HumanContentRepresentation,
};
use evertrace_store::JournalPayload;

use super::{
    HumanContentState, HumanGovernanceError, HumanGovernanceService, HumanSemanticContent,
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
        // The semantic value is exact, never a journal envelope or a CAS path.
        let text = if row.object_kind.as_deref() == Some("revision_proposal_revision") {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let JournalPayload::RevisionProposalRecorded(value) = payload else {
                return Err(HumanGovernanceError::Store);
            };
            if representation == HumanContentRepresentation::Text {
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
