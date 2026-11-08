//! Bounded kernel data reads. No presentation, diagnostics or background work.
use super::EngineService;
use evertrace_domain::{error::ErrorCode, query::HumanContentState};
use evertrace_store::ObjectRow;
use std::time::Instant;

/// Canonical read-only source/repository assessment, shared with existing detail/export readers.
pub(super) async fn check_source_access(
    writer: &crate::WriterHandle,
    report: Option<&evertrace_codex::HostProbeReport>,
    all_rows: &[ObjectRow],
    rows: &[&ObjectRow],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    let authority = crate::repository::RepositoryReadAuthority::retained(report);
    for chunk in rows.chunks(usize::from(evertrace_domain::query::METADATA_READ_LIMIT)) {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted);
        }
        if !crate::session_import::source_rows_read_assessment(
            writer,
            &authority,
            all_rows,
            chunk,
            None,
            Some(deadline),
        )
        .await
        .map_err(|_| ErrorCode::StoreCorrupt)?
        .0
        .is_empty()
        {
            return Err(ErrorCode::Untrusted);
        }
    }
    let scopes = crate::repository::row_repository_contexts_from_scopes(all_rows.iter(), rows)
        .map_err(|_| ErrorCode::StoreCorrupt)?;
    if !crate::repository::repository_read_assessment(
        writer,
        scopes.values().flatten().copied().collect(),
        &authority,
        deadline,
    )
    .await
    .map_err(|_| ErrorCode::StoreCorrupt)?
    .0
    .is_empty()
    {
        return Err(ErrorCode::Untrusted);
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::ResourceExhausted);
    }
    Ok(())
}

/// A storage byte window, not the Python title/excerpt policy. Preserve scalar types and array positions.
fn stored_value_window(
    value: serde_json::Value,
    remaining: &mut usize,
) -> Option<(serde_json::Value, bool)> {
    use serde_json::Value as V;
    match value {
        V::String(text) => {
            if *remaining < 2 {
                return None;
            }
            let bounds = std::iter::once(0)
                .chain(text.char_indices().skip(1).map(|(index, _)| index))
                .chain(std::iter::once(text.len()))
                .take_while(|index| *index <= remaining.saturating_sub(2))
                .collect::<Vec<_>>();
            let (mut low, mut high) = (0, bounds.len());
            while low + 1 < high {
                let middle = (low + high) / 2;
                if serde_json::to_vec(&text[..bounds[middle]]).ok()?.len() <= *remaining {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            let end = bounds[low];
            let prefix = V::String(text[..end].to_owned());
            *remaining -= serde_json::to_vec(&prefix).ok()?.len();
            Some((prefix, end == text.len()))
        }
        V::Array(values) => {
            if *remaining < 2 {
                return None;
            }
            *remaining -= 2;
            let length = values.len();
            let (mut window, mut complete) = (Vec::new(), true);
            for value in values {
                let comma = usize::from(!window.is_empty());
                let Some(mut available) = remaining.checked_sub(comma) else {
                    complete = false;
                    break;
                };
                let Some((value, full)) = stored_value_window(value, &mut available) else {
                    complete = false;
                    break;
                };
                *remaining = available;
                complete &= full;
                window.push(value);
            }
            complete &= window.len() == length;
            Some((V::Array(window), complete))
        }
        V::Object(values) => {
            if *remaining < 2 {
                return None;
            }
            *remaining -= 2;
            let length = values.len();
            let (mut window, mut complete) = (serde_json::Map::new(), true);
            for (index, (key, value)) in values.into_iter().enumerate() {
                let overhead =
                    serde_json::to_vec(&key).ok()?.len() + 1 + usize::from(!window.is_empty());
                let Some(available) = remaining.checked_sub(overhead) else {
                    complete = false;
                    break;
                };
                // Share bytes across stored sibling fields; a long string must not hide every later field.
                let allocation = available / (length - index);
                let mut unused = allocation;
                let Some((value, full)) = stored_value_window(value, &mut unused) else {
                    complete = false;
                    break;
                };
                *remaining -= overhead + allocation - unused;
                complete &= full;
                window.insert(key, value);
            }
            complete &= window.len() == length;
            Some((V::Object(window), complete))
        }
        value => {
            let bytes = serde_json::to_vec(&value).ok()?.len();
            *remaining = remaining.checked_sub(bytes)?;
            Some((value, true))
        }
    }
}

fn bounded_stored_fields(
    fields: serde_json::Value,
) -> Result<(serde_json::Value, Vec<String>), ErrorCode> {
    let limit = usize::from(evertrace_domain::query::HUMAN_CONTENT_LIMIT);
    // Probe exact encoding with a fixed-size buffer, never a full allocation of an oversized value.
    let mut encoded = vec![0_u8; limit];
    if serde_json::to_writer(std::io::Cursor::new(encoded.as_mut_slice()), &fields).is_ok() {
        return Ok((fields, Vec::new()));
    }
    let serde_json::Value::Object(fields) = fields else {
        return Err(ErrorCode::StoreCorrupt);
    };
    let mut remaining = limit - 2;
    let length = fields.len();
    let (mut window, mut truncated) = (serde_json::Map::new(), Vec::new());
    for (index, (key, value)) in fields.into_iter().enumerate() {
        let overhead = serde_json::to_vec(&key)
            .map_err(|_| ErrorCode::Internal)?
            .len()
            + 1
            + usize::from(!window.is_empty());
        let Some(available) = remaining.checked_sub(overhead) else {
            truncated.push(key);
            continue;
        };
        let allocation = available / (length - index);
        let mut unused = allocation;
        match stored_value_window(value, &mut unused) {
            Some((value, complete)) => {
                remaining -= overhead + allocation - unused;
                if !complete {
                    truncated.push(key.clone());
                }
                window.insert(key, value);
            }
            None => truncated.push(key),
        }
    }
    Ok((serde_json::Value::Object(window), truncated))
}

fn fields_metadata(
    context: &evertrace_store::projections::StoredFieldsContext,
) -> Result<evertrace_domain::query::ExactStoredFields, ErrorCode> {
    use evertrace_domain::query::{ExactFieldIdentity, ExactStoredFields, HumanContentState};
    let selection = context
        .selected
        .as_ref()
        .map(|root| {
            Ok(ExactFieldIdentity {
                object_kind: root.object_kind.clone().ok_or(ErrorCode::StoreCorrupt)?,
                object_ref: root.object_id.clone().ok_or(ErrorCode::StoreCorrupt)?,
                revision_ref: root
                    .current_revision_id
                    .clone()
                    .ok_or(ErrorCode::StoreCorrupt)?,
                source_event_seq: root.source_event_seq,
            })
        })
        .transpose()?;
    Ok(ExactStoredFields {
        state: context.state.clone(),
        selection,
        content_state: HumanContentState::Missing,
        fields: None,
        fields_complete: false,
        truncated_fields: Vec::new(),
        source_observation_refs: Vec::new(),
    })
}

async fn fields_access(
    writer: &crate::WriterHandle,
    context: &evertrace_store::projections::StoredFieldsContext,
    report: &std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    deadline: Instant,
) -> Result<(), ErrorCode> {
    if context.source_suppressed {
        return Err(ErrorCode::Untrusted);
    }
    let references = context.rows.iter().collect::<Vec<_>>();
    let host = report.read().await.clone();
    check_source_access(writer, host.as_ref(), &context.rows, &references, deadline).await
}

fn denied_fields(result: &mut evertrace_domain::query::ExactStoredFields, code: ErrorCode) {
    use evertrace_domain::query::HumanContentState as State;
    result.content_state = if code == ErrorCode::Untrusted {
        State::AccessDenied
    } else {
        State::Unavailable
    };
    result.fields = None;
    result.fields_complete = false;
    result.truncated_fields.clear();
    result.source_observation_refs.clear();
}

fn source_records(
    context: &evertrace_store::projections::StoredFieldsContext,
) -> Result<
    (
        evertrace_domain::evidence::SourceReceipt,
        evertrace_domain::evidence::SourceObservation,
    ),
    ErrorCode,
> {
    use evertrace_store::JournalPayload as P;
    let decode = |row: &ObjectRow| {
        serde_json::from_str::<P>(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
            .map_err(|_| ErrorCode::StoreCorrupt)
    };
    let root = context.selected.as_ref().ok_or(ErrorCode::StoreCorrupt)?;
    match decode(root)? {
        P::SourceReceiptRecorded(receipt) => {
            let row = context
                .rows
                .iter()
                .find(|row| {
                    row.object_kind.as_deref() == Some("source_observation")
                        && row.object_id.as_deref()
                            == Some(receipt.source_observation_id.to_string().as_str())
                })
                .ok_or(ErrorCode::StoreCorrupt)?;
            let P::SourceObservationRecorded(observation) = decode(row)? else {
                return Err(ErrorCode::StoreCorrupt);
            };
            Ok((*receipt, *observation))
        }
        P::SourceObservationRecorded(observation) => {
            let row = context
                .rows
                .iter()
                .find(|row| {
                    row.object_kind.as_deref() == Some("source_receipt")
                        && row.object_id.as_deref()
                            == Some(observation.source_receipt_ref.to_string().as_str())
                })
                .ok_or(ErrorCode::StoreCorrupt)?;
            let P::SourceReceiptRecorded(receipt) = decode(row)? else {
                return Err(ErrorCode::StoreCorrupt);
            };
            Ok((*receipt, *observation))
        }
        _ => Err(ErrorCode::InvalidInput),
    }
}

fn source_identity(
    receipt: &evertrace_domain::evidence::SourceReceipt,
    observation: &evertrace_domain::evidence::SourceObservation,
) -> evertrace_domain::query::ExactSourceIdentity {
    evertrace_domain::query::ExactSourceIdentity {
        observation_ref: observation.source_observation_id,
        receipt_ref: receipt.source_receipt_id,
        source_instance_ref: receipt.source_instance_id.clone(),
        source_revision: receipt.source_revision.clone(),
        source_record_identity: receipt.source_record_identity.clone(),
        payload_fingerprint: observation.payload_fingerprint.clone(),
        protected_bytes: receipt.protected_length,
        original_bytes: receipt.original_length,
    }
}

fn utf8_window(
    mut bytes: Vec<u8>,
    offset: u64,
    length: u16,
    total_bytes: u64,
) -> Result<evertrace_domain::query::ExactUtf8Window, ErrorCode> {
    if offset > total_bytes {
        return Err(ErrorCode::InvalidInput);
    }
    let span = u64::from(length).min(total_bytes - offset) as usize;
    if bytes.len() < span {
        return Err(ErrorCode::StoreCorrupt);
    }
    let continuation = |byte: &u8| byte & 0xc0 == 0x80;
    let start_boundary = bytes.first().is_none_or(|byte| !continuation(byte));
    let end_boundary = bytes.get(span).is_none_or(|byte| !continuation(byte));
    let mut leading = 0;
    while leading < span && continuation(&bytes[leading]) {
        leading += 1;
    }
    let mut trailing = span;
    while trailing > leading && bytes.get(trailing).is_some_and(continuation) {
        trailing -= 1;
    }
    bytes.truncate(trailing);
    bytes.drain(..leading);
    Ok(evertrace_domain::query::ExactUtf8Window {
        start: offset + leading as u64,
        end: offset + trailing as u64,
        total_bytes,
        start_boundary,
        end_boundary,
        text: String::from_utf8(bytes).map_err(|_| ErrorCode::StoreCorrupt)?,
    })
}

/// Serialize a single selected Domain record without allocating its complete JSON representation.
struct RecordWindowWriter<'a> {
    start: u64,
    end: u64,
    position: u64,
    bytes: Vec<u8>,
    check: &'a dyn Fn() -> Result<(), ErrorCode>,
}

impl std::io::Write for RecordWindowWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        (self.check)().map_err(|_| std::io::Error::other("exact record read cancelled"))?;
        let next = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("record length overflow"))?;
        let start = self.start.max(self.position);
        let end = self.end.min(next);
        if start < end {
            self.bytes.extend_from_slice(
                &bytes[(start - self.position) as usize..(end - self.position) as usize],
            );
        }
        self.position = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn record_json<T: serde::Serialize>(
    value: &T,
    range: &evertrace_domain::query::ExactUtf8Range,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<evertrace_domain::query::ExactUtf8Window, ErrorCode> {
    let mut writer = RecordWindowWriter {
        start: range.offset,
        end: range.offset + u64::from(range.length) + 1,
        position: 0,
        bytes: Vec::new(),
        check,
    };
    let result = serde_json::to_writer_pretty(&mut writer, value);
    check()?;
    result.map_err(|_| ErrorCode::StoreCorrupt)?;
    utf8_window(writer.bytes, range.offset, range.length, writer.position)
}

fn record_text(
    value: &str,
    range: &evertrace_domain::query::ExactUtf8Range,
) -> Result<evertrace_domain::query::ExactUtf8Window, ErrorCode> {
    let start = (range.offset.min(value.len() as u64)) as usize;
    let end = (range.offset + u64::from(range.length) + 1).min(value.len() as u64) as usize;
    utf8_window(
        value.as_bytes()[start..end].to_vec(),
        range.offset,
        range.length,
        value.len() as u64,
    )
}

type RecordData = (
    evertrace_domain::query::ExactRecordInfo,
    Option<evertrace_domain::query::ExactUtf8Window>,
);

fn semantic_record<T: serde::Serialize>(
    value: &T,
    text: Option<&str>,
    query: &evertrace_domain::query::ExactRecordQuery,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<Option<RecordData>, ErrorCode> {
    use evertrace_domain::query::{ExactRecordField as Field, ExactRecordInfo as Info};
    let window = match (&query.field, &query.range) {
        (None, None) => None,
        (Some(Field::Json), Some(range)) => Some(record_json(value, range, check)?),
        (Some(Field::Text), Some(range)) if text.is_some() => {
            Some(record_text(text.unwrap(), range)?)
        }
        _ => return Ok(None),
    };
    Ok(Some((
        Info::Semantic {
            text_bytes: text.map(|value| value.len() as u64),
        },
        window,
    )))
}

/// Only the selected revision supplies a CAS coordinate; external references are never opened.
fn artifact_record(
    value: &evertrace_domain::work::WorkArtifact,
    rows: &[ObjectRow],
    query: &evertrace_domain::query::ExactRecordQuery,
    cas_dir: &std::path::Path,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<(HumanContentState, Option<RecordData>), ErrorCode> {
    use evertrace_capture::{CasError, CasStore};
    use evertrace_domain::query::{
        ExactRecordField as Field, ExactRecordInfo as Info, HumanContentState as State,
    };
    use evertrace_domain::work::ArtifactPayloadStatus as Status;
    use evertrace_store::JournalPayload as P;
    value.validate().map_err(|_| ErrorCode::StoreCorrupt)?;
    let blob = value.revision.content_blob_ref.filter(|_| {
        matches!(
            value.revision.payload_status,
            Status::Available | Status::Degraded
        )
    });
    let mut source_pair = None;
    if let Some(blob) = blob {
        let expected = blob.to_string();
        for id in &value.revision.source_observation_refs {
            check()?;
            let Some(row) = rows.iter().find(|row| {
                row.object_kind.as_deref() == Some("source_observation")
                    && row.object_id.as_deref() == Some(id.to_string().as_str())
            }) else {
                return Ok((State::Unavailable, None));
            };
            let P::SourceObservationRecorded(observation) =
                serde_json::from_str(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
                    .map_err(|_| ErrorCode::StoreCorrupt)?
            else {
                return Err(ErrorCode::StoreCorrupt);
            };
            let Some(row) = rows.iter().find(|row| {
                row.object_kind.as_deref() == Some("source_receipt")
                    && row.object_id.as_deref()
                        == Some(observation.source_receipt_ref.to_string().as_str())
            }) else {
                return Ok((State::Unavailable, None));
            };
            let P::SourceReceiptRecorded(receipt) =
                serde_json::from_str(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
                    .map_err(|_| ErrorCode::StoreCorrupt)?
            else {
                return Err(ErrorCode::StoreCorrupt);
            };
            if expected.strip_prefix("cas:") == Some(receipt.cas_ref.as_str()) {
                // A broken matching source proof must not fall back to a less restrictive blob read.
                evertrace_capture::cas::SourceArchiveVerifier::new(&receipt, &observation)
                    .map_err(|_| ErrorCode::StoreCorrupt)?;
                if source_pair.is_none() {
                    source_pair = Some((receipt, observation));
                }
            }
        }
    }
    let info = Info::Artifact {
        source: source_pair
            .as_ref()
            .map(|(receipt, observation)| Box::new(source_identity(receipt, observation))),
    };
    if query.field == Some(Field::Text) {
        let Some(blob) = blob else {
            return Ok((State::Unsupported, None));
        };
        let Some(range) = &query.range else {
            return Ok((State::Unsupported, None));
        };
        let media = value
            .revision
            .media_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if !(media.starts_with("text/")
            || matches!(media.as_str(), "application/json" | "application/x-ndjson"))
        {
            return Ok((State::Unsupported, None));
        }
        let Ok(cas) = CasStore::open_existing(cas_dir.to_path_buf()) else {
            return Ok((State::Unavailable, None));
        };
        let mut checkpoint = || check().map_err(|_| CasError::ReadCancelled);
        let bytes = range.offset..range.offset + u64::from(range.length) + 1;
        let read = if let Some((receipt, observation)) = &source_pair {
            if matches!(
                receipt.protected_presentation,
                Some(evertrace_domain::evidence::ProtectedPresentation::Unavailable { .. })
            ) {
                return Ok((State::Unsupported, None));
            }
            cas.read_source_text_window_checked(receipt, observation, bytes, &mut checkpoint)
        } else {
            let digest = evertrace_domain::evidence::hex(&blob.as_digest())
                .parse()
                .map_err(|_| ErrorCode::StoreCorrupt)?;
            cas.read_text_window_checked(&digest, bytes, &mut checkpoint)
        };
        return match read {
            Ok((window, true)) => Ok((
                State::Ready,
                Some((
                    info,
                    Some(utf8_window(
                        window.bytes,
                        range.offset,
                        range.length,
                        window.total_bytes,
                    )?),
                )),
            )),
            Ok((_, false)) => Ok((State::Unsupported, None)),
            Err(CasError::ReadBudgetExceeded) => Ok((State::TooLarge, None)),
            Err(CasError::ReadCancelled) => Err(ErrorCode::ResourceExhausted),
            Err(_) => Ok((State::Unavailable, None)),
        };
    }
    let data = semantic_record(value, None, query, check)?.map(|(_, window)| (info, window));
    Ok((
        if data.is_some() {
            State::Ready
        } else {
            State::Unsupported
        },
        data,
    ))
}

fn record_data(
    payload: evertrace_store::JournalPayload,
    query: &evertrace_domain::query::ExactRecordQuery,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<Option<RecordData>, ErrorCode> {
    use evertrace_domain::query::{ExactRecordField as Field, ExactRecordInfo as Info};
    use evertrace_store::JournalPayload as P;
    payload.validate().map_err(|_| ErrorCode::StoreCorrupt)?;
    check()?;
    match payload {
        P::AtomRecorded(value) => semantic_record(&value, Some(&value.value.text), query, check),
        P::ProcedureRevisionRecorded(value) => semantic_record(&value, None, query, check),
        P::CoreMembershipRecorded(value) => semantic_record(&value, None, query, check),
        P::GlobalSupportContractRecorded(value) => semantic_record(&value, None, query, check),
        P::GlobalSupportValidationRecorded(value) => semantic_record(&value, None, query, check),
        P::SemanticDigestRecorded(value) => semantic_record(&value, None, query, check),
        P::RevisionProposalRecorded(value) => semantic_record(&value, None, query, check),
        P::AttemptRecorded(value) => semantic_record(&value, None, query, check),
        P::OperationBurstRecorded(value) => semantic_record(&value, None, query, check),
        P::OperationDerived(value) => semantic_record(&value, None, query, check),
        P::HostOccurrenceNormalized(value) => semantic_record(&value, None, query, check),
        P::ScopeEffectDerived(value) => semantic_record(&value, None, query, check),
        P::WorktreeInstanceRecorded(value) => semantic_record(&value, None, query, check),
        P::WorktreeSnapshotRecorded(value) => semantic_record(&value, None, query, check),
        P::RecoveryCaptureRequestRecorded(value) => semantic_record(&value, None, query, check),
        P::RecoveryBundleRecorded(value) => semantic_record(&value, None, query, check),
        P::CaptureReceiptRecorded(value) => semantic_record(&value, None, query, check),
        P::ExperimentRunRecorded(value) => semantic_record(&value, None, query, check),
        P::ResultEvidenceRecorded(value) => semantic_record(&value, None, query, check),
        P::ProcedureUsageRecorded(value) => semantic_record(&value, None, query, check),
        P::ProcedureNegativeEvidenceRecorded(value) => semantic_record(&value, None, query, check),
        P::ProcedureNegativeReviewRecorded(value) => semantic_record(&value, None, query, check),
        P::RecallLedgerRecorded(event) => match *event {
            evertrace_domain::recall::RecallLedgerEvent::NeedRecorded { need } => {
                Ok(semantic_record(&need, None, query, check)?
                    .map(|(_, window)| (Info::CurrentRecall, window)))
            }
            _ => Ok(None),
        },
        P::TaskRecorded(value) => {
            semantic_record(&value, Some(&value.canonical_goal), query, check)
        }
        P::WorkstreamRecorded(value) => {
            semantic_record(&value, Some(&value.workstream_goal), query, check)
        }
        P::WorkEpisodeRecorded(value) => {
            let info = Info::Work {
                goal_bytes: value.phase_contract.local_goal.len() as u64,
                open_loop_bytes: value
                    .open_loops
                    .iter()
                    .map(|entry| entry.len() as u64)
                    .collect(),
            };
            let window = match (&query.field, &query.range) {
                (None, None) => None,
                (Some(Field::Json), Some(range)) => Some(record_json(&value, range, check)?),
                (Some(Field::Goal), Some(range)) => {
                    Some(record_text(&value.phase_contract.local_goal, range)?)
                }
                (Some(Field::OpenLoop { index }), Some(range)) => Some(record_text(
                    value
                        .open_loops
                        .get(*index as usize)
                        .ok_or(ErrorCode::InvalidInput)?,
                    range,
                )?),
                _ => return Ok(None),
            };
            Ok(Some((info, window)))
        }
        _ => Ok(None),
    }
}

impl EngineService {
    /// One immutable, gated source byte range. No global projection, page state or persistent read ticket.
    pub async fn read_exact_source(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::ExactSourceTextQuery>,
        effective_config_hash: [u8; 32],
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
        cas_dir: std::path::PathBuf,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ExactSourceWindow>,
        ErrorCode,
    > {
        use evertrace_domain::query::{ExactReadQuery, ExactSourceWindow, SourceTextField};
        use evertrace_domain::query::{HumanContentState as State, MetadataReadOutcome as Outcome};
        if !query.validate() {
            return Err(ErrorCode::InvalidInput);
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        let request = Box::new(ExactReadQuery::SourceText((*query).clone()));
        let Outcome::Page(before) = writer
            .read_stored_fields_context(
                request.clone(),
                cancelled.clone(),
                deadline,
                effective_config_hash,
            )
            .await
            .map_err(|_| ErrorCode::Internal)?
        else {
            return Err(ErrorCode::ResourceExhausted);
        };
        if query
            .expected_data_identity
            .is_some_and(|identity| identity != before.state.data_identity)
        {
            return Ok(Outcome::Conflict(before.state.frontier));
        }
        let metadata = fields_metadata(&before)?;
        let mut result = ExactSourceWindow {
            field: query.field,
            state: metadata.state,
            selection: metadata.selection,
            content_state: State::Missing,
            source: None,
            window: None,
        };
        let Some(root) = &before.selected else {
            return Ok(Outcome::Page(Box::new(result)));
        };
        if root.row_id != query.reference.stable_key
            && root.object_id.as_deref() != Some(&query.reference.stable_key)
        {
            result.content_state = State::Unavailable;
            return Ok(Outcome::Page(Box::new(result)));
        }
        if let Err(code) = fields_access(&writer, &before, &report, deadline).await {
            result.content_state = if code == ErrorCode::Untrusted {
                State::AccessDenied
            } else {
                State::Unavailable
            };
            return Ok(Outcome::Page(Box::new(result)));
        }
        let (receipt, observation) = source_records(&before)?;
        let source = source_identity(&receipt, &observation);
        if query
            .expected_source
            .as_ref()
            .is_some_and(|expected| *expected != source)
        {
            return Ok(Outcome::Conflict(before.state.frontier));
        }
        if matches!(
            receipt.protected_presentation,
            Some(evertrace_domain::evidence::ProtectedPresentation::Unavailable { .. })
        ) {
            result.content_state = State::Unsupported;
            return Ok(Outcome::Page(Box::new(result)));
        }
        let presentation = if query.field == SourceTextField::Presentation {
            use evertrace_domain::evidence::ProtectedPresentation as P;
            let text = match &receipt.protected_presentation {
                Some(P::Inline { text } | P::Preview { text }) => text,
                _ => {
                    result.content_state = State::Unsupported;
                    return Ok(Outcome::Page(Box::new(result)));
                }
            };
            query
                .range
                .as_ref()
                .map(|range| record_text(text, range))
                .transpose()?
        } else {
            evertrace_capture::cas::SourceArchiveVerifier::new(&receipt, &observation)
                .map_err(|_| ErrorCode::StoreCorrupt)?;
            None
        };
        let read = if let Some(range) = query
            .range
            .clone()
            .filter(|_| query.field == SourceTextField::Protected)
        {
            let bytes = range.offset..range.offset + u64::from(range.length) + 1;
            Some(
                writer
                    .read_handle()
                    .read_blocking(move |cancel| {
                        let check = || {
                            cancel.check()?;
                            if Instant::now() >= deadline {
                                return Err(evertrace_store::StoreError::Io);
                            }
                            Ok(())
                        };
                        check()?;
                        let cas = evertrace_capture::CasStore::open_existing(cas_dir)
                            .map_err(|_| evertrace_store::StoreError::Io)?;
                        let result = cas
                            .read_source_text_window_checked(
                                &receipt,
                                &observation,
                                bytes,
                                &mut || {
                                    check().map_err(|_| evertrace_capture::CasError::ReadCancelled)
                                },
                            )
                            .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?;
                        check()?;
                        Ok(result)
                    })
                    .await,
            )
        } else {
            None
        };
        let Outcome::Page(current) = writer
            .read_stored_fields_context(request, cancelled, deadline, effective_config_hash)
            .await
            .map_err(|_| ErrorCode::Internal)?
        else {
            return Err(ErrorCode::ResourceExhausted);
        };
        result.state = current.state.clone();
        result.selection = fields_metadata(&current)?.selection;
        if let Err(code) = fields_access(&writer, &current, &report, deadline).await {
            result.content_state = if code == ErrorCode::Untrusted {
                State::AccessDenied
            } else {
                State::Unavailable
            };
        } else if current.selected.is_none() {
            result.content_state = State::Missing;
        } else if before.state.data_identity != current.state.data_identity
            || before.selected != current.selected
            || before.rows != current.rows
        {
            return Ok(Outcome::Conflict(current.state.frontier));
        } else if matches!(read, Some(Err(_))) {
            result.content_state = State::Unavailable;
        } else if matches!(read, Some(Ok((_, false)))) {
            result.content_state = State::Unsupported;
        } else {
            if let (Some(Ok((window, _))), Some(range)) = (read, query.range.as_ref()) {
                result.window = Some(utf8_window(
                    window.bytes,
                    range.offset,
                    range.length,
                    window.total_bytes,
                )?);
            }
            if query.field == SourceTextField::Presentation {
                result.window = presentation;
            }
            result.source = Some(source);
            result.content_state = State::Ready;
        }
        if !result.validate() {
            return Err(ErrorCode::ResourceExhausted);
        }
        Ok(Outcome::Page(Box::new(result)))
    }

    /// Complete stored record values and closed text fields, never a management projection or Journal wrapper.
    pub async fn read_exact_record(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::ExactRecordQuery>,
        effective_config_hash: [u8; 32],
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
        cas_dir: std::path::PathBuf,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ExactRecordWindow>,
        ErrorCode,
    > {
        use evertrace_domain::query::{ExactReadQuery, ExactRecordWindow};
        use evertrace_domain::query::{HumanContentState as State, MetadataReadOutcome as Outcome};
        if !query.validate() {
            return Err(ErrorCode::InvalidInput);
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        let request = Box::new(ExactReadQuery::Record((*query).clone()));
        let before = match writer
            .read_stored_fields_context(
                request.clone(),
                cancelled.clone(),
                deadline,
                effective_config_hash,
            )
            .await
            .map_err(|_| ErrorCode::Internal)?
        {
            Outcome::Page(context) => context,
            Outcome::Conflict(frontier) => return Ok(Outcome::Conflict(frontier)),
            Outcome::TooLarge => return Err(ErrorCode::ResourceExhausted),
        };
        if query
            .expected_data_identity
            .is_some_and(|identity| identity != before.state.data_identity)
        {
            return Ok(Outcome::Conflict(before.state.frontier));
        }
        let metadata = fields_metadata(&before)?;
        let mut result = ExactRecordWindow {
            state: metadata.state,
            selection: metadata.selection,
            metadata: None,
            content_state: State::Missing,
            info: None,
            window: None,
        };
        let Some(root) = &before.selected else {
            return Ok(Outcome::Page(Box::new(result)));
        };
        if root.row_id != query.reference.stable_key
            && root.object_id.as_deref() != Some(&query.reference.stable_key)
            && query.reference.revision_ref.as_deref() != Some(query.reference.stable_key.as_str())
        {
            result.content_state = State::Unavailable;
            return Ok(Outcome::Page(Box::new(result)));
        }
        result.metadata = Some(evertrace_store::JournalWriter::metadata_record(root, None));
        if query
            .expected_selection
            .as_ref()
            .is_some_and(|expected| Some(expected) != result.selection.as_ref())
        {
            return Ok(Outcome::Conflict(before.state.frontier));
        }
        if let Err(code) = fields_access(&writer, &before, &report, deadline).await {
            result.content_state = if code == ErrorCode::Untrusted {
                State::AccessDenied
            } else {
                State::Unavailable
            };
            return Ok(Outcome::Page(Box::new(result)));
        }
        let (read_state, data) = if matches!(
            root.object_kind.as_deref(),
            Some("source_receipt" | "source_observation")
        ) {
            if query.field.is_some() {
                (State::Unsupported, None)
            } else {
                let (receipt, observation) = source_records(&before)?;
                let record = evertrace_domain::source::SourceRecordMetadata::from_records(
                    &receipt,
                    &observation,
                )
                .ok_or(ErrorCode::StoreCorrupt)?;
                (
                    State::Ready,
                    Some((
                        evertrace_domain::query::ExactRecordInfo::Source {
                            record: Box::new(record),
                            source: Box::new(source_identity(&receipt, &observation)),
                            source_kind: receipt.source_kind,
                            source_session_ref: receipt.source_session_ref,
                        },
                        None,
                    )),
                )
            }
        } else {
            let payload = root.payload_json.clone().ok_or(ErrorCode::StoreCorrupt)?;
            let selected_query = query.clone();
            let current_effect = root.object_kind.as_deref() == Some("procedure_context_effect");
            let source_rows = if root.object_kind.as_deref() == Some("work_artifact") {
                before
                    .rows
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.object_kind.as_deref(),
                            Some("source_receipt" | "source_observation")
                        )
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            writer
                .read_handle()
                .read_blocking(move |cancel| {
                    let check = || {
                        cancel.check().map_err(|_| ErrorCode::ResourceExhausted)?;
                        if Instant::now() >= deadline {
                            return Err(ErrorCode::ResourceExhausted);
                        }
                        Ok(())
                    };
                    let read = || {
                        check()?;
                        if current_effect {
                            let value: evertrace_domain::procedure::ProcedureContextEffectProjection =
                                serde_json::from_str(&payload).map_err(|_| ErrorCode::StoreCorrupt)?;
                            value.validate().map_err(|_| ErrorCode::StoreCorrupt)?;
                            let data = semantic_record(&value, None, &selected_query, &check)?
                                .map(|(_, window)| (evertrace_domain::query::ExactRecordInfo::CurrentProcedureEffect, window));
                            check()?;
                            return Ok((if data.is_some() { State::Ready } else { State::Unsupported }, data));
                        }
                        let payload =
                            serde_json::from_str(&payload).map_err(|_| ErrorCode::StoreCorrupt)?;
                        let data =
                            if let evertrace_store::JournalPayload::WorkArtifactRecorded(value) =
                                payload
                            {
                                artifact_record(
                                    &value,
                                    &source_rows,
                                    &selected_query,
                                    &cas_dir,
                                    &check,
                                )?
                            } else {
                                let data = record_data(payload, &selected_query, &check)?;
                                (
                                    if data.is_some() {
                                        State::Ready
                                    } else {
                                        State::Unsupported
                                    },
                                    data,
                                )
                            };
                        check()?;
                        Ok(data)
                    };
                    Ok(read())
                })
                .await
                .map_err(|_| ErrorCode::ResourceExhausted)??
        };
        let current = match writer
            .read_stored_fields_context(request, cancelled, deadline, effective_config_hash)
            .await
            .map_err(|_| ErrorCode::Internal)?
        {
            Outcome::Page(context) => context,
            Outcome::Conflict(frontier) => return Ok(Outcome::Conflict(frontier)),
            Outcome::TooLarge => return Err(ErrorCode::ResourceExhausted),
        };
        result.state = current.state.clone();
        result.selection = fields_metadata(&current)?.selection;
        result.metadata = current
            .selected
            .as_ref()
            .map(|row| evertrace_store::JournalWriter::metadata_record(row, None));
        if let Err(code) = fields_access(&writer, &current, &report, deadline).await {
            result.content_state = if code == ErrorCode::Untrusted {
                State::AccessDenied
            } else {
                State::Unavailable
            };
        } else if current.selected.is_none() {
            result.content_state = State::Missing;
        } else if before.state.data_identity != current.state.data_identity
            || before.selected != current.selected
            || before.rows != current.rows
        {
            return Ok(Outcome::Conflict(current.state.frontier));
        } else {
            result.content_state = read_state;
            if let Some((info, window)) = data {
                result.info = Some(info);
                result.window = window;
            }
        }
        if !result.validate() {
            return Err(ErrorCode::ResourceExhausted);
        }
        Ok(Outcome::Page(Box::new(result)))
    }

    /// Immutable stored fields only. Recheck the same finite dependency closure before disclosure.
    pub async fn read_exact_fields(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::ExactFieldsQuery>,
        effective_config_hash: [u8; 32],
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    ) -> Result<evertrace_domain::query::ExactStoredFields, ErrorCode> {
        use evertrace_domain::query::{
            ExactReadQuery, HumanContentState as State, MetadataReadOutcome,
        };
        let query = Box::new(ExactReadQuery::Fields(*query));
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        let context = writer
            .read_stored_fields_context(
                query.clone(),
                cancelled.clone(),
                deadline,
                effective_config_hash,
            )
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let MetadataReadOutcome::Page(context) = context else {
            return Err(ErrorCode::ResourceExhausted);
        };
        let mut result = fields_metadata(&context)?;
        let Some(root) = &context.selected else {
            return Ok(result);
        };
        if let Err(code) = fields_access(&writer, &context, &report, deadline).await {
            denied_fields(&mut result, code);
            return Ok(result);
        }
        let payload: evertrace_store::JournalPayload = serde_json::from_str(
            root.payload_json
                .as_deref()
                .ok_or(ErrorCode::StoreCorrupt)?,
        )
        .map_err(|_| ErrorCode::StoreCorrupt)?;
        use evertrace_store::JournalPayload as P;
        let fields = match payload {
            P::AtomRecorded(value) => {
                serde_json::json!({"kind": value.kind, "scope": value.scope, "value": value.value})
            }
            P::ProcedureRevisionRecorded(value) => serde_json::json!({"draft": value.draft}),
            P::RevisionProposalRecorded(value) => {
                serde_json::json!({
                    "payload": value.payload, "status": value.status,
                    "eligibility": value.eligibility, "operation": value.operation,
                })
            }
            P::CoreMembershipRecorded(value) => {
                serde_json::json!({"atom_revision_id": value.atom_revision_id, "active": value.active})
            }
            P::SemanticDigestRecorded(value) => {
                serde_json::json!({"application": value.application, "status": value.status})
            }
            P::WorkEpisodeRecorded(value) => {
                serde_json::json!({"phase_contract": value.phase_contract, "open_loops": value.open_loops})
            }
            _ => return Err(ErrorCode::InvalidInput),
        };
        let (fields, truncated_fields) = bounded_stored_fields(fields)?;
        let current = writer
            .read_stored_fields_context(query, cancelled, deadline, effective_config_hash)
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let MetadataReadOutcome::Page(current) = current else {
            return Err(ErrorCode::ResourceExhausted);
        };
        if context.state.data_identity != current.state.data_identity
            || context.selected != current.selected
            || context.rows != current.rows
            || current.source_suppressed
        {
            result.content_state = State::Unavailable;
            return Ok(result);
        }
        if let Err(code) = fields_access(&writer, &current, &report, deadline).await {
            denied_fields(&mut result, code);
            return Ok(result);
        }
        result.state = current.state;
        result.content_state = State::Ready;
        result.fields = Some(fields);
        result.fields_complete = truncated_fields.is_empty();
        result.truncated_fields = truncated_fields;
        result.source_observation_refs = current
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
            .filter_map(|row| row.object_id.clone())
            .collect();
        Ok(result)
    }

    /// Same-binding exact pair and original access gates only; field comparison belongs to Python.
    pub async fn read_revision_pair(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::RevisionCompareQuery>,
        effective_config_hash: [u8; 32],
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
        cas_dir: std::path::PathBuf,
    ) -> Result<evertrace_domain::query::RevisionPairFields, ErrorCode> {
        use evertrace_domain::query::{
            ExactFieldsQuery, HumanContentState as State, MetadataReadOutcome as Outcome,
        };
        use evertrace_domain::query::{HumanRevisionKind as Kind, RevisionPairFields};
        for reference in [&query.left, &query.right] {
            if !(ExactFieldsQuery {
                revision_ref: reference.revision_ref.clone(),
            })
            .validate()
            {
                return Err(ErrorCode::InvalidInput);
            }
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        let before = writer
            .read_stored_pair_context(
                query.clone(),
                cancelled.clone(),
                deadline,
                effective_config_hash,
            )
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let Outcome::Page(before) = before else {
            return Err(ErrorCode::ResourceExhausted);
        };
        if before.len() != 2 {
            return Err(ErrorCode::StoreCorrupt);
        }
        let mut sides = Vec::with_capacity(2);
        for (context, reference) in before.iter().zip([&query.left, &query.right]) {
            let mut side = fields_metadata(context)?;
            if let Some(root) = &context.selected {
                if root.row_id != reference.stable_key {
                    side.content_state = State::Unavailable;
                } else if let Err(code) = fields_access(&writer, context, &report, deadline).await {
                    denied_fields(&mut side, code);
                } else {
                    let payload: evertrace_store::JournalPayload = serde_json::from_str(
                        root.payload_json
                            .as_deref()
                            .ok_or(ErrorCode::StoreCorrupt)?,
                    )
                    .map_err(|_| ErrorCode::StoreCorrupt)?;
                    use evertrace_store::JournalPayload as P;
                    let value = match payload {
                        P::AtomRecorded(value) => Some(serde_json::to_value(value)),
                        P::ProcedureRevisionRecorded(value) => Some(serde_json::to_value(value)),
                        P::CoreMembershipRecorded(value) => Some(serde_json::to_value(value)),
                        P::RevisionProposalRecorded(value) => Some(serde_json::to_value(value)),
                        P::SemanticDigestRecorded(value) => Some(serde_json::to_value(value)),
                        P::ResultEvidenceRecorded(value) => Some(serde_json::to_value(value)),
                        _ => None,
                    };
                    if let Some(value) = value {
                        let (fields, truncated) =
                            bounded_stored_fields(value.map_err(|_| ErrorCode::StoreCorrupt)?)?;
                        side.content_state = State::Ready;
                        side.fields = Some(fields);
                        side.fields_complete = truncated.is_empty();
                        side.truncated_fields = truncated;
                    } else {
                        side.content_state = State::Unsupported;
                    }
                }
            }
            sides.push(side);
        }
        let mut result_assessment = None;
        if sides.iter().all(|side| {
            side.content_state == State::Ready
                && side
                    .selection
                    .as_ref()
                    .is_some_and(|value| value.object_kind == "result_evidence")
        }) {
            let mut members = Vec::with_capacity(2);
            for context in before.iter() {
                use evertrace_store::JournalPayload as P;
                let root = context.selected.as_ref().ok_or(ErrorCode::StoreCorrupt)?;
                let P::ResultEvidenceRecorded(result) = serde_json::from_str(
                    root.payload_json
                        .as_deref()
                        .ok_or(ErrorCode::StoreCorrupt)?,
                )
                .map_err(|_| ErrorCode::StoreCorrupt)?
                else {
                    return Err(ErrorCode::StoreCorrupt);
                };
                let run_revision = result.experiment_run_revision_id.to_string();
                let row = context
                    .rows
                    .iter()
                    .find(|row| {
                        row.object_kind.as_deref() == Some("experiment_run")
                            && row.current_revision_id.as_deref() == Some(run_revision.as_str())
                    })
                    .ok_or(ErrorCode::StoreCorrupt)?;
                let P::ExperimentRunRecorded(run) = serde_json::from_str(
                    row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?,
                )
                .map_err(|_| ErrorCode::StoreCorrupt)?
                else {
                    return Err(ErrorCode::StoreCorrupt);
                };
                members.push((result, run));
            }
            let stop = cancelled.clone();
            result_assessment = Some(
                tokio::task::spawn_blocking(move || {
                    let refs = members
                        .iter()
                        .map(|(result, run)| (result.as_ref(), run.as_ref()))
                        .collect::<Vec<_>>();
                    crate::autoresearch::read_result_cohort(&cas_dir, &refs, &mut || {
                        if stop.load(std::sync::atomic::Ordering::SeqCst)
                            || Instant::now() >= deadline
                        {
                            Err(evertrace_capture::CasError::ReadCancelled)
                        } else {
                            Ok(())
                        }
                    })
                })
                .await
                .map_err(|_| ErrorCode::Internal)?
                .map_err(|_| ErrorCode::StoreCorrupt)?,
            );
        }
        let after = writer
            .read_stored_pair_context(query.clone(), cancelled, deadline, effective_config_hash)
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let Outcome::Page(after) = after else {
            return Err(ErrorCode::ResourceExhausted);
        };
        if after.len() != 2 {
            return Err(ErrorCode::StoreCorrupt);
        }
        for ((old, current), side) in before.iter().zip(after.iter()).zip(&mut sides) {
            side.state = current.state.clone();
            if old.state.data_identity != current.state.data_identity
                || old.selected != current.selected
                || old.rows != current.rows
                || old.source_suppressed != current.source_suppressed
            {
                denied_fields(side, ErrorCode::Internal);
            } else if side.content_state == State::Ready {
                if let Err(code) = fields_access(&writer, current, &report, deadline).await {
                    denied_fields(side, code);
                } else {
                    side.source_observation_refs = current
                        .rows
                        .iter()
                        .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
                        .filter_map(|row| row.object_id.clone())
                        .collect();
                }
            }
        }
        let mut sides = sides.into_iter();
        let left = sides.next().ok_or(ErrorCode::StoreCorrupt)?;
        let right = sides.next().ok_or(ErrorCode::StoreCorrupt)?;
        let object_kind =
            if left.content_state == State::Ready && right.content_state == State::Ready {
                let a = left.selection.as_ref().ok_or(ErrorCode::StoreCorrupt)?;
                let b = right.selection.as_ref().ok_or(ErrorCode::StoreCorrupt)?;
                if a.object_kind != b.object_kind
                    || (a.object_kind != "result_evidence" && a.object_ref != b.object_ref)
                {
                    return Err(ErrorCode::InvalidInput);
                }
                Some(match a.object_kind.as_str() {
                    "atom_revision" => Kind::Atom,
                    "procedure_revision" => Kind::Procedure,
                    "core_membership" => Kind::CoreMembership,
                    "revision_proposal_revision" => Kind::Proposal,
                    "semantic_digest" => Kind::Digest,
                    "result_evidence" => Kind::Result,
                    _ => return Err(ErrorCode::InvalidInput),
                })
            } else {
                None
            };
        if object_kind != Some(Kind::Result) {
            result_assessment = None;
        }
        let result = RevisionPairFields {
            query: *query,
            object_kind,
            left,
            right,
            result_assessment,
        };
        if !result.validate() {
            return Err(ErrorCode::ResourceExhausted);
        }
        Ok(result)
    }

    async fn read_scopes_metadata(
        writer: &crate::WriterHandle,
        query: &evertrace_domain::query::ScopeDirectoryQuery,
        after: Option<&str>,
        limit: u16,
        state: &evertrace_domain::query::ObjectReadState,
        config_hash: [u8; 32],
        cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
        deadline: Instant,
        report: &std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ScopeMetadataPage>,
        crate::WriterActorError,
    > {
        use evertrace_domain::query::{
            HumanContentState as S, MemoryScopeSelection as Selection, MetadataReadOutcome as O,
            ScopeMetadataPage, ScopeMetadataRecord,
        };
        use evertrace_store::JournalPayload as P;
        let mut page = ScopeMetadataPage {
            query: query.clone(),
            parent_available: true,
            names_complete: true,
            records: Vec::new(),
            matching_count: None,
            next: None,
        };
        let mut scan_after = None;
        let mut found_after = after.is_none();
        let mut count = 0_u64;
        let needle = query.name.to_lowercase();
        // This normalization is only a Native full-domain name predicate, not a directory label.
        let matches_name = |value: &str| {
            value.to_lowercase().contains(&needle)
                || value
                    .split(|ch: char| ch.is_whitespace() || ch.is_control())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase()
                    .contains(&needle)
        };
        loop {
            let context = writer
                .read_scope_metadata_context(
                    query,
                    scan_after.as_deref(),
                    cancelled.clone(),
                    deadline,
                    config_hash,
                )
                .await?;
            let (current, context) = match context {
                O::Page(context) => *context,
                O::TooLarge => return Ok(O::TooLarge),
                O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
            };
            if current != *state {
                return Ok(O::Conflict(current.frontier));
            }
            if !context.parent_available {
                page.parent_available = false;
                page.names_complete = false;
                return Ok(O::Page(Box::new(page)));
            }
            for candidate in context.items {
                if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(crate::WriterActorError::Store);
                }
                if Instant::now() >= deadline {
                    return Ok(O::TooLarge);
                }
                found_after |= after == Some(candidate.row.row_id.as_str());
                let payload: P = serde_json::from_str(
                    candidate
                        .row
                        .payload_json
                        .as_deref()
                        .ok_or(crate::WriterActorError::StoreCorrupt)?,
                )
                .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
                let mut record = ScopeMetadataRecord {
                    stable_key: candidate.row.row_id.clone(),
                    selection: Selection::All,
                    path_hint: None,
                    branch_hint: candidate.branch_ref,
                    lifecycle: None,
                    repository_user_disabled: false,
                    repository_trust_revoked: false,
                    has_children: candidate.has_children,
                    goal: None,
                    goal_state: S::Unsupported,
                };
                let repository = match &payload {
                    P::RepositoryInstanceRecorded(repo) => Some(repo.as_ref()),
                    _ => candidate.repository.as_ref(),
                };
                if let Some(repo) = repository {
                    record.repository_user_disabled = repo.user_disabled;
                    record.repository_trust_revoked = repo
                        .capability_state
                        .as_ref()
                        .is_some_and(|v| v.trust_revoked);
                }
                let id = match payload {
                    P::RepositoryInstanceRecorded(repo) => {
                        record.selection = Selection::Repository {
                            repository_id: repo.repository_id,
                        };
                        record.path_hint = Some(repo.current_path);
                        repo.repository_id.to_string()
                    }
                    P::WorktreeInstanceRecorded(tree) => {
                        record.selection = Selection::Worktree {
                            worktree_id: tree.worktree_instance_id,
                        };
                        record.path_hint = tree.current_path;
                        record.lifecycle = Some(
                            match tree.lifecycle {
                                evertrace_domain::repository::WorktreeLifecycle::Active => "active",
                                evertrace_domain::repository::WorktreeLifecycle::Missing => {
                                    "missing"
                                }
                                evertrace_domain::repository::WorktreeLifecycle::Removed => {
                                    "removed"
                                }
                                evertrace_domain::repository::WorktreeLifecycle::Pruned => "pruned",
                                evertrace_domain::repository::WorktreeLifecycle::Archived => {
                                    "archived"
                                }
                            }
                            .into(),
                        );
                        tree.worktree_instance_id.to_string()
                    }
                    P::TaskRecorded(task) => {
                        record.selection = Selection::Task {
                            task_id: task.task_id,
                        };
                        record.lifecycle = Some(task.lifecycle.as_str().into());
                        record.goal_state = S::Unavailable;
                        if candidate.sources_complete {
                            // Consume this bounded cohort instead of cloning its metadata/payload buffers.
                            let mut all = std::collections::BTreeMap::new();
                            let mut selected = std::collections::BTreeSet::new();
                            selected.insert(candidate.row.row_id.clone());
                            all.insert(candidate.row.row_id.clone(), candidate.row);
                            for row in candidate.source_rows {
                                selected.insert(row.row_id.clone());
                                all.insert(row.row_id.clone(), row);
                            }
                            for row in candidate.source_scope_rows {
                                all.insert(row.row_id.clone(), row);
                            }
                            let all = all.into_values().collect::<Vec<_>>();
                            let selected = all
                                .iter()
                                .filter(|row| selected.contains(&row.row_id))
                                .collect::<Vec<_>>();
                            let bytes = selected
                                .iter()
                                .map(|row| row.payload_json.as_ref().map_or(0, |value| value.len()))
                                .sum::<usize>();
                            if selected.len() <= 4096 && bytes <= 64 * 1024 * 1024 {
                                let host = report.read().await.clone();
                                let access = if candidate.source_suppressed {
                                    Err(ErrorCode::Untrusted)
                                } else {
                                    check_source_access(
                                        writer,
                                        host.as_ref(),
                                        &all,
                                        &selected,
                                        deadline,
                                    )
                                    .await
                                };
                                record.goal_state = match access {
                                    Ok(()) => {
                                        record.goal = Some(task.canonical_goal);
                                        S::Ready
                                    }
                                    Err(ErrorCode::Untrusted) => S::AccessDenied,
                                    Err(_) => S::Unavailable,
                                };
                            }
                        }
                        page.names_complete &= record.goal_state == S::Ready;
                        task.task_id.to_string()
                    }
                    _ => return Err(crate::WriterActorError::StoreCorrupt),
                };
                let matches = needle.is_empty()
                    || matches_name(&id)
                    || record.path_hint.as_ref().is_some_and(|v| matches_name(v))
                    || record.branch_hint.as_ref().is_some_and(|v| matches_name(v))
                    || record.goal.as_ref().is_some_and(|v| matches_name(v));
                if !matches {
                    continue;
                }
                count = count
                    .checked_add(1)
                    .ok_or(crate::WriterActorError::StoreCorrupt)?;
                if after.is_none_or(|key| record.stable_key.as_str() > key)
                    && page.records.len() <= usize::from(limit)
                {
                    page.records.push(record);
                }
            }
            scan_after = context.next_cursor;
            if scan_after.is_none() {
                break;
            }
        }
        if !found_after {
            return Err(crate::WriterActorError::InvalidInput);
        }
        if page.records.len() > usize::from(limit) {
            page.records.truncate(usize::from(limit));
            page.next = page.records.last().map(|row| row.stable_key.clone());
        }
        // Unknown protected names must not become an exact zero or a keyword-presence oracle.
        page.matching_count = (needle.is_empty() || page.names_complete).then_some(count);
        Ok(O::Page(Box::new(page)))
    }

    async fn read_archive_metadata(
        writer: &crate::WriterHandle,
        query: &evertrace_domain::source::SourceArchiveQuery,
        after: Option<&evertrace_domain::source::SourceArchivePosition>,
        limit: u16,
        state: &evertrace_domain::query::ObjectReadState,
        config_hash: [u8; 32],
        cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
        deadline: Instant,
        report: &std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<
            evertrace_domain::source::SourceArchiveMetadataPage,
        >,
        crate::WriterActorError,
    > {
        use evertrace_domain::query::{HumanContentState as S, MetadataReadOutcome as O};
        let (current, context) = match writer
            .read_archive_metadata_context(
                query,
                after,
                limit,
                cancelled.clone(),
                deadline,
                config_hash,
            )
            .await?
        {
            O::Page(context) => *context,
            O::TooLarge => return Ok(O::TooLarge),
            O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
        };
        if current != *state {
            return Ok(O::Conflict(current.frontier));
        }
        let mut page = context.page;
        if page.state == S::Ready {
            let host = report.read().await.clone();
            let authority = crate::repository::RepositoryReadAuthority::retained(host.as_ref());
            let sources = [(query.source().to_owned(), query.source().to_owned())]
                .into_iter()
                .collect();
            let source = crate::session_import::source_instance_read_assessment(
                writer,
                &authority,
                sources,
                Some(deadline),
            )
            .await
            .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
            let references = context.references.iter().collect::<Vec<_>>();
            let scopes = crate::repository::row_repository_contexts_from_scopes(
                context.scope_rows.iter(),
                &references,
            )?;
            let repositories = crate::repository::repository_read_assessment(
                writer,
                scopes.values().flatten().copied().collect(),
                &authority,
                deadline,
            )
            .await?;
            if context.suppressed || !source.0.is_empty() || !repositories.0.is_empty() {
                page.clear(S::AccessDenied);
            }
            if Instant::now() >= deadline {
                return Ok(O::TooLarge);
            }
        }
        Ok(O::Page(Box::new(page)))
    }

    async fn read_reference_metadata(
        writer: &crate::WriterHandle,
        reference: &evertrace_domain::query::ExactRecordRef,
        after: Option<&str>,
        limit: u16,
        state: &evertrace_domain::query::ObjectReadState,
        config_hash: [u8; 32],
        cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
        deadline: Instant,
        report: &std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<
            evertrace_domain::query::ReferenceMetadataPage,
        >,
        crate::WriterActorError,
    > {
        use evertrace_domain::query::{HumanContentState as S, MetadataReadOutcome as O};
        let context = match writer
            .read_reference_metadata_context(
                reference,
                after,
                limit,
                cancelled.clone(),
                deadline,
                config_hash,
            )
            .await?
        {
            O::Page(context) => *context,
            O::TooLarge => return Ok(O::TooLarge),
            O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
        };
        if context.source.state != *state {
            return Ok(O::Conflict(context.source.state.frontier));
        }
        let mut page = context.page;
        if page.content_state == S::Ready {
            if let Err(error) = fields_access(writer, &context.source, report, deadline).await {
                page.clear(if error == ErrorCode::Untrusted {
                    S::AccessDenied
                } else {
                    S::Unavailable
                });
            } else {
                for (record, context) in page.records.iter_mut().zip(context.targets.iter()) {
                    if let Some(context) = context
                        && let Err(error) = fields_access(writer, context, report, deadline).await
                    {
                        record.content_state = if error == ErrorCode::Untrusted {
                            S::AccessDenied
                        } else {
                            S::Unavailable
                        };
                        record.metadata = None;
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Ok(O::TooLarge);
        }
        Ok(O::Page(Box::new(page)))
    }

    pub async fn read_metadata_batch(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::MetadataBatchQuery>,
        effective_config_hash: [u8; 32],
        llm: &evertrace_domain::config::LlmConfig,
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ObjectReadBatch>,
        crate::WriterActorError,
    > {
        use evertrace_domain::query::{
            MetadataBatchQuery, MetadataReadOutcome as O, MetadataReadPage as P,
            MetadataReadQuery as Q, ObjectReadBatch,
        };
        if !query.validate() {
            return Err(crate::WriterActorError::InvalidInput);
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        let read = async {
            if !query.items.iter().any(|item| {
                matches!(
                    item,
                    Q::Scopes { .. } | Q::Archive { .. } | Q::References { .. }
                )
            }) {
                return Self::read_stored_metadata_batch(
                    writer,
                    query,
                    effective_config_hash,
                    llm,
                    report,
                    cancelled.clone(),
                    deadline,
                )
                .await;
            }
            let state = Self::read_state(writer.read_handle(), effective_config_hash)
                .await
                .map_err(|_| crate::WriterActorError::Store)?;
            if query.expected_frontier.is_some_and(|v| v != state.frontier)
                || query
                    .expected_data_identity
                    .is_some_and(|v| v != state.data_identity)
            {
                return Ok(O::Conflict(state.frontier));
            }
            let stored = query
                .items
                .iter()
                .filter(|item| {
                    !matches!(
                        item,
                        Q::Scopes { .. } | Q::Archive { .. } | Q::References { .. }
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            let mut stored = if stored.is_empty() {
                Vec::new()
            } else {
                match Self::read_stored_metadata_batch(
                    writer.clone(),
                    Box::new(MetadataBatchQuery {
                        expected_frontier: Some(state.frontier),
                        expected_data_identity: Some(state.data_identity),
                        items: stored,
                    }),
                    effective_config_hash,
                    llm,
                    report.clone(),
                    cancelled.clone(),
                    deadline,
                )
                .await?
                {
                    O::Page(batch) if batch.state == state => batch.items,
                    O::Page(batch) => return Ok(O::Conflict(batch.state.frontier)),
                    O::TooLarge => return Ok(O::TooLarge),
                    O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
                }
            }
            .into_iter();
            let mut items = Vec::with_capacity(query.items.len());
            for item in &query.items {
                items.push(
                    if let Q::Scopes {
                        query,
                        after,
                        limit,
                    } = item
                    {
                        match Self::read_scopes_metadata(
                            &writer,
                            query,
                            after.as_deref(),
                            *limit,
                            &state,
                            effective_config_hash,
                            &cancelled,
                            deadline,
                            &report,
                        )
                        .await?
                        {
                            O::Page(page) => P::Scopes { page },
                            O::TooLarge => return Ok(O::TooLarge),
                            O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
                        }
                    } else if let Q::Archive {
                        query,
                        after,
                        limit,
                    } = item
                    {
                        match Self::read_archive_metadata(
                            &writer,
                            query,
                            after.as_ref(),
                            *limit,
                            &state,
                            effective_config_hash,
                            &cancelled,
                            deadline,
                            &report,
                        )
                        .await?
                        {
                            O::Page(page) => P::Archive { page },
                            O::TooLarge => return Ok(O::TooLarge),
                            O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
                        }
                    } else if let Q::References {
                        reference,
                        after,
                        limit,
                    } = item
                    {
                        match Self::read_reference_metadata(
                            &writer,
                            reference,
                            after.as_deref(),
                            *limit,
                            &state,
                            effective_config_hash,
                            &cancelled,
                            deadline,
                            &report,
                        )
                        .await?
                        {
                            O::Page(page) => P::References { page },
                            O::TooLarge => return Ok(O::TooLarge),
                            O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
                        }
                    } else {
                        stored.next().ok_or(crate::WriterActorError::StoreCorrupt)?
                    },
                );
            }
            let current = Self::read_state(writer.read_handle(), effective_config_hash)
                .await
                .map_err(|_| crate::WriterActorError::Store)?;
            if current != state {
                return Ok(O::Conflict(current.frontier));
            }
            let batch = ObjectReadBatch { state, items };
            Ok(if batch.validate() {
                O::Page(Box::new(batch))
            } else {
                O::TooLarge
            })
        };
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), read).await {
            Ok(result) => result,
            Err(_) => Ok(O::TooLarge),
        }
    }

    async fn read_stored_metadata_batch(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::MetadataBatchQuery>,
        effective_config_hash: [u8; 32],
        llm: &evertrace_domain::config::LlmConfig,
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        deadline: Instant,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ObjectReadBatch>,
        crate::WriterActorError,
    > {
        use evertrace_domain::query::{
            ExactFieldsQuery, ExactReadQuery, HumanContentState as S, MetadataReadOutcome as O,
            MetadataReadPage as P,
        };
        let mut outcome = writer
            .read_metadata_batch(query, cancelled.clone(), effective_config_hash, deadline)
            .await?;
        if let evertrace_domain::query::MetadataReadOutcome::Page(batch) = &mut outcome {
            for item in &mut batch.items {
                let source = match &*item {
                    P::Revisions { page } if page.content_state == S::Ready => Some((
                        evertrace_domain::query::ExactRecordRef {
                            stable_key: page.reference.stable_key.clone(),
                            revision_ref: Some(page.reference.revision_ref.clone()),
                        },
                        false,
                    )),
                    P::Sources { page } if page.state == S::Ready => page
                        .selection_ref
                        .clone()
                        .map(|reference| (reference, true)),
                    _ => None,
                };
                if let Some((reference, logical)) = source {
                    let revision = reference
                        .revision_ref
                        .as_ref()
                        .ok_or(crate::WriterActorError::StoreCorrupt)?;
                    let context = writer
                        .read_stored_fields_context(
                            Box::new(ExactReadQuery::Fields(ExactFieldsQuery {
                                revision_ref: revision.clone(),
                            })),
                            cancelled.clone(),
                            deadline,
                            effective_config_hash,
                        )
                        .await?;
                    let context = match context {
                        O::Page(context) => context,
                        O::TooLarge => return Ok(O::TooLarge),
                        O::Conflict(frontier) => return Ok(O::Conflict(frontier)),
                    };
                    if context.state != batch.state {
                        return Ok(O::Conflict(context.state.frontier));
                    }
                    let state = if context.selected.as_ref().is_none_or(|row| {
                        (row.row_id != reference.stable_key
                            && !(logical
                                && row.object_id.as_deref() == Some(reference.stable_key.as_str())))
                            || row.current_revision_id.as_deref() != Some(revision)
                    }) {
                        Some(S::Missing)
                    } else {
                        fields_access(&writer, &context, &report, deadline)
                            .await
                            .err()
                            .map(|code| {
                                if code == ErrorCode::Untrusted {
                                    S::AccessDenied
                                } else {
                                    S::Unavailable
                                }
                            })
                    };
                    if let Some(state) = state {
                        match item {
                            P::Revisions { page } => {
                                page.content_state = state;
                                page.records.clear();
                                page.matching_count = None;
                                page.next = None;
                            }
                            P::Sources { page } => page.clear(state),
                            _ => unreachable!(),
                        }
                    }
                }
                if let evertrace_domain::query::MetadataReadPage::Work { page } = item {
                    page.llm_enabled = Some(llm.enabled);
                    page.episode_enrichment_enabled = Some(
                        llm.episode_enrichment != evertrace_domain::config::EpisodeEnrichment::Off,
                    );
                }
            }
            // Counts and membership are fixed at batch.state, including across current-source assessments.
            if batch
                .items
                .iter()
                .any(|item| matches!(item, P::Revisions { .. }) || matches!(item, P::Sources { page }
                    if matches!(page.query.selection, evertrace_domain::query::MemoryScopeSelection::Task { .. })))
            {
                let current = match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    Self::read_state(writer.read_handle(), effective_config_hash),
                )
                .await
                {
                    Ok(state) => state.map_err(|_| crate::WriterActorError::Store)?,
                    Err(_) => return Ok(O::TooLarge),
                };
                if current != batch.state {
                    return Ok(O::Conflict(current.frontier));
                }
            }
            if !batch.validate() {
                return Ok(evertrace_domain::query::MetadataReadOutcome::TooLarge);
            }
        }
        Ok(outcome)
    }

    pub async fn read_jobs(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::JobsReadQuery>,
        effective_config_hash: [u8; 32],
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ObjectReadJobs>,
        crate::WriterActorError,
    > {
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        writer
            .read_jobs(query, cancelled, effective_config_hash)
            .await
    }

    pub async fn read_state(
        reader: evertrace_store::StoreReadHandle,
        effective_config_hash: [u8; 32],
    ) -> Result<evertrace_domain::query::ObjectReadState, evertrace_store::StoreError> {
        let (frontier, data_identity) = reader.state().await?;
        Ok(evertrace_domain::query::ObjectReadState {
            frontier,
            data_identity,
            effective_config_hash: evertrace_domain::evidence::hex(&effective_config_hash),
        })
    }
}
