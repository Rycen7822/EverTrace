//! Bounded kernel data reads. No presentation, diagnostics or background work.
use super::EngineService;
use evertrace_domain::error::ErrorCode;
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
    for chunk in rows.chunks(usize::from(evertrace_domain::query::METADATA_READ_LIMIT)) {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted);
        }
        if !crate::session_import::source_rows_read_assessment(
            writer,
            report,
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
        report,
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

impl EngineService {
    /// Immutable stored fields only. Recheck the same finite dependency closure before disclosure.
    pub async fn read_exact_fields(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::ExactFieldsQuery>,
        effective_config_hash: [u8; 32],
        report: std::sync::Arc<tokio::sync::RwLock<Option<evertrace_codex::HostProbeReport>>>,
    ) -> Result<evertrace_domain::query::ExactStoredFields, ErrorCode> {
        use evertrace_domain::query::{
            ExactFieldIdentity, ExactStoredFields, HumanContentState as State, MetadataReadOutcome,
        };
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
        let mut result = ExactStoredFields {
            state: context.state.clone(),
            selection: None,
            content_state: State::Missing,
            fields: None,
            fields_complete: false,
            truncated_fields: Vec::new(),
            source_observation_refs: Vec::new(),
        };
        let Some(root) = &context.selected else {
            return Ok(result);
        };
        result.selection = Some(ExactFieldIdentity {
            object_kind: root.object_kind.clone().ok_or(ErrorCode::StoreCorrupt)?,
            object_ref: root.object_id.clone().ok_or(ErrorCode::StoreCorrupt)?,
            revision_ref: root
                .current_revision_id
                .clone()
                .ok_or(ErrorCode::StoreCorrupt)?,
            source_event_seq: root.source_event_seq,
        });
        if context.source_suppressed {
            result.content_state = State::AccessDenied;
            return Ok(result);
        }
        let references = context.rows.iter().collect::<Vec<_>>();
        let host = report.read().await.clone();
        if let Err(code) =
            check_source_access(&writer, host.as_ref(), &context.rows, &references, deadline).await
        {
            result.content_state = if code == ErrorCode::Untrusted {
                State::AccessDenied
            } else {
                State::Unavailable
            };
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
        let references = current.rows.iter().collect::<Vec<_>>();
        let host = report.read().await.clone();
        if let Err(code) =
            check_source_access(&writer, host.as_ref(), &current.rows, &references, deadline).await
        {
            result.content_state = if code == ErrorCode::Untrusted {
                State::AccessDenied
            } else {
                State::Unavailable
            };
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

    pub async fn read_metadata_batch(
        writer: crate::WriterHandle,
        query: Box<evertrace_domain::query::MetadataBatchQuery>,
        effective_config_hash: [u8; 32],
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<evertrace_domain::query::ObjectReadBatch>,
        crate::WriterActorError,
    > {
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        writer
            .read_metadata_batch(query, cancelled, effective_config_hash)
            .await
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
