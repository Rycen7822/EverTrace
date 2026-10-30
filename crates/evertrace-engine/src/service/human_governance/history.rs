//! Same-object metadata only. Body access is rechecked by the exact detail read.
use super::*;
use evertrace_domain::query::ObjectRevisionsCursor;

pub(super) fn page(
    snapshot: &ProjectionSnapshot,
    source: &ObjectRow,
    request: HumanRelatedRequest<'_>,
) -> Result<HumanPage, HumanGovernanceError> {
    if !matches!(
        source.object_kind.as_deref(),
        Some(
            "atom_revision"
                | "procedure_revision"
                | "core_membership"
                | "revision_proposal_revision"
                | "semantic_digest"
        )
    ) || source.object_id.is_none()
    {
        return Err(HumanGovernanceError::InvalidInput);
    }
    let after = request
        .after
        .map(|value| {
            let cursor: ObjectRevisionsCursor =
                serde_json::from_str(value).map_err(|_| HumanGovernanceError::InvalidInput)?;
            cursor
                .validate_for(
                    request.source_stable_key,
                    request.expected_source_revision_ref,
                    request.expected_frontier,
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            Ok::<_, HumanGovernanceError>(cursor)
        })
        .transpose()?;
    if let Some(cursor) = &after
        && !snapshot.data_rows().any(|row| {
            row.row_id == cursor.row_id
                && row.source_event_seq == cursor.source_event_seq
                && row.object_id == source.object_id
                && row.object_kind == source.object_kind
                && row.row_class == Some(ObjectRowClass::Object)
        })
    {
        return Err(HumanGovernanceError::InvalidInput);
    }
    let rank = |seq: u64, key: &str| (u64::MAX - seq, key.to_owned());
    let after_rank = after
        .as_ref()
        .map(|cursor| rank(cursor.source_event_seq, &cursor.row_id));
    // Do not resolve revision aliases through unrelated compiled projections.
    // Retain only limit+1 metadata references, not all revisions or their bodies.
    let mut selected = BTreeMap::new();
    for row in snapshot.data_rows().filter(|row| {
        row.object_id == source.object_id
            && row.object_kind == source.object_kind
            && row.row_class == Some(ObjectRowClass::Object)
    }) {
        let position = rank(row.source_event_seq, &row.row_id);
        if after_rank.as_ref().is_some_and(|after| position <= *after) {
            continue;
        }
        selected.insert(position, row);
        if selected.len() > usize::from(request.limit) + 1 {
            selected.pop_last();
        }
    }
    let mut rows = selected.into_values().collect::<Vec<_>>();
    let next_cursor = if rows.len() > usize::from(request.limit) {
        let last = rows[usize::from(request.limit) - 1];
        Some(
            serde_json::to_string(&ObjectRevisionsCursor {
                frontier: snapshot.frontier,
                source_key: source.row_id.clone(),
                source_revision: request.expected_source_revision_ref.to_owned(),
                source_event_seq: last.source_event_seq,
                row_id: last.row_id.clone(),
            })
            .map_err(|_| HumanGovernanceError::Store)?,
        )
    } else {
        None
    };
    rows.truncate(usize::from(request.limit));
    let (status, degraded_reasons) = snapshot_status(snapshot)?;
    Ok(HumanPage {
        diagnostics: None,
        frontier: snapshot.frontier,
        status,
        degraded_reasons,
        items: rows
            .into_iter()
            .map(|row| summary_fields(row, HumanSurface::Explorer))
            .collect(),
        next_cursor,
    })
}
