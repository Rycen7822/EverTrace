use super::presentation::READ_DEADLINE;
use super::*;
use evertrace_domain::{evidence::ProtectedPresentation, query::HumanContentState, source::*};

impl HumanGovernanceService {
    pub async fn source_archive(
        &self,
        query: SourceArchiveQuery,
        expected_frontier: Option<u64>,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<SourceArchivePage, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if !(1..=32).contains(&limit) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let cursor = after
            .map(|raw| {
                if raw.len() > 4096 {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                let cursor: SourceArchiveCursor =
                    serde_json::from_str(raw).map_err(|_| HumanGovernanceError::InvalidInput)?;
                if !cursor.validate_for(&query) || expected_frontier != Some(cursor.frontier) {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                Ok(cursor)
            })
            .transpose()?;
        let context = self
            .writer
            .source_archive_context(&query, cursor.as_ref(), usize::from(limit))
            .await
            .map_err(|error| {
                if error == crate::WriterActorError::InvalidInput {
                    HumanGovernanceError::InvalidInput
                } else {
                    HumanGovernanceError::Store
                }
            })?;
        let (context, found, authorization) = match context {
            evertrace_store::SourceArchiveCurrentContext::Revisions(page) => {
                return Ok(if expected_frontier.is_some_and(|f| f != page.frontier) {
                    Err(page.frontier)
                } else {
                    Ok(page)
                });
            }
            evertrace_store::SourceArchiveCurrentContext::Records {
                context,
                found,
                authorization,
                ..
            } => (context, found, authorization),
        };
        if expected_frontier.is_some_and(|f| f != context.frontier) {
            return Ok(Err(context.frontier));
        }
        let mut page = SourceArchivePage {
            frontier: context.frontier,
            query: query.clone(),
            state: if found {
                HumanContentState::Ready
            } else {
                HumanContentState::Missing
            },
            entries: SourceArchiveEntries::Records {
                records: Vec::new(),
            },
            next_cursor: context.next_cursor,
        };
        let deadline = std::time::Instant::now() + READ_DEADLINE;
        let mut records = Vec::with_capacity(context.items.len());
        let had_records = !context.items.is_empty();
        if found && !had_records && authorization.is_none() {
            page.state = HumanContentState::Missing;
            page.next_cursor = None;
            return Ok(Ok(page));
        }
        for current in context
            .items
            .into_iter()
            .map(|item| (item, true))
            .chain(authorization.into_iter().map(|item| (*item, false)))
        {
            let (current, emit) = current;
            let source_count = current.source_rows.len();
            let mut rows = current.source_rows;
            rows.extend(current.scope_rows);
            let direct = rows[..source_count].iter().collect::<Vec<_>>();
            match self
                .readable_directory_sources(&rows, &direct, current.suppressed, deadline)
                .await
            {
                Ok(()) => {}
                Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                Err(error) => {
                    page.state = if matches!(error, export::Failure::Denied) {
                        HumanContentState::AccessDenied
                    } else {
                        HumanContentState::Unavailable
                    };
                    page.next_cursor = None;
                    return Ok(Ok(page));
                }
            }
            if !emit {
                continue;
            }
            let mut receipt = None;
            let mut observation = None;
            for row in &rows[..source_count] {
                let payload: JournalPayload = serde_json::from_str(
                    row.payload_json
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
                match payload {
                    JournalPayload::SourceReceiptRecorded(value) => receipt = Some(value),
                    JournalPayload::SourceObservationRecorded(value) => observation = Some(value),
                    _ => {}
                }
            }
            let (receipt, observation) = receipt
                .zip(observation)
                .ok_or(HumanGovernanceError::Store)?;
            if observation.source_receipt_ref != receipt.source_receipt_id
                || observation.source_observation_id != receipt.source_observation_id
                || receipt.source_instance_id.as_str() != query.source()
                || !matches!(&query,SourceArchiveQuery::Records{source_revision,..} if source_revision==&receipt.source_revision)
            {
                return Err(HumanGovernanceError::Store);
            }
            let (presentation, text) = match receipt.protected_presentation.as_ref() {
                Some(ProtectedPresentation::Inline { text }) => {
                    (SourceRecordPresentation::Inline, Some(text))
                }
                Some(ProtectedPresentation::Preview { text }) => {
                    (SourceRecordPresentation::Preview, Some(text))
                }
                Some(ProtectedPresentation::Unavailable { .. }) => {
                    (SourceRecordPresentation::NonText, None)
                }
                None => (SourceRecordPresentation::NotRecorded, None),
            };
            let preview = text.map(|text| {
                let mut end = text.len().min(512);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text[..end].to_owned()
            });
            let record = SourceRecordSummary {
                metadata: SourceRecordMetadata {
                    stable_key: current.selected.row_id,
                    observation_id: observation.source_observation_id,
                    receipt_id: receipt.source_receipt_id,
                    record_identity: receipt.source_record_identity,
                    sequence: receipt.source_sequence,
                    byte_range: receipt.source_byte_range,
                    observation_role: receipt.observation_role,
                    source_role: observation.source_role,
                    content_trust: observation.content_trust,
                    completeness: receipt.capture_completeness,
                    archive_mode: receipt.archive_mode,
                    event_time_us: receipt.event_time_us,
                    recorded_at_us: receipt.recorded_at_us,
                    event_time_provenance: receipt.event_time_provenance,
                    presentation,
                },
                preview_truncated: text.is_some_and(|text| text.len() > 512),
                preview,
            };
            if !record.validate() {
                return Err(HumanGovernanceError::Store);
            }
            records.push(record);
        }
        if std::time::Instant::now() >= deadline {
            page.state = HumanContentState::Unavailable;
            page.next_cursor = None;
        } else {
            page.entries = SourceArchiveEntries::Records { records };
        }
        Ok(Ok(page))
    }
}
