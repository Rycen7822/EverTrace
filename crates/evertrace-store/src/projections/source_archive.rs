//! Source-local archive reads over the existing rebuildable receipt/watermark index.
use super::*;
use evertrace_domain::{query::HumanContentState, source::*};

#[derive(Debug)]
pub enum SourceArchiveCurrentContext {
    Revisions(SourceArchivePage),
    Records {
        context: CaptureCurrentContext,
        found: bool,
        authorization: Option<Box<CaptureCurrentItem>>,
    },
}
/// Native-only authorization inputs; source receipt text/payloads never enter a metadata batch.
#[derive(Debug)]
pub struct SourceArchiveMetadataContext {
    pub page: SourceArchiveMetadataPage,
    pub scope_rows: Vec<ObjectRow>,
    pub references: Vec<ObjectRow>,
    pub suppressed: bool,
}

impl JournalAdmissionState {
    pub(crate) fn source_archive_metadata(
        &self,
        query: &SourceArchiveQuery,
        after: Option<&SourceArchivePosition>,
        limit: u16,
        cancelled: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
    ) -> Result<
        evertrace_domain::query::MetadataReadOutcome<SourceArchiveMetadataContext>,
        StoreError,
    > {
        use evertrace_domain::query::MetadataReadOutcome as O;
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if !(1..=32).contains(&limit) || after.is_some_and(|v| !v.validate_for(query)) {
            return Err(StoreError::InvalidInput);
        }
        let entries = match query {
            SourceArchiveQuery::Revisions { .. } => SourceArchiveMetadataEntries::Revisions {
                revisions: Vec::new(),
            },
            SourceArchiveQuery::Records { .. } => SourceArchiveMetadataEntries::Records {
                records: Vec::new(),
            },
        };
        let mut context = SourceArchiveMetadataContext {
            page: SourceArchiveMetadataPage {
                query: query.clone(),
                state: HumanContentState::Missing,
                entries,
                matching_count: None,
                next: None,
            },
            scope_rows: Vec::new(),
            references: Vec::new(),
            suppressed: false,
        };
        let check = || {
            if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                Err(StoreError::Io)
            } else {
                Ok(())
            }
        };
        check()?;
        if !self.source_catalog_contains(query.source())? {
            return Ok(O::Page(Box::new(context)));
        }
        match query {
            SourceArchiveQuery::Revisions { source_instance_id } => {
                let Some(source) = self.source_watermarks.get(source_instance_id) else {
                    return Ok(O::Page(Box::new(context)));
                };
                if let Some(SourceArchivePosition::Revision { revision }) = after
                    && !source.revisions.contains_key(revision)
                {
                    return Err(StoreError::InvalidInput);
                }
                let mut selected = Vec::new();
                for revision in source.revisions.keys() {
                    check()?;
                    if std::time::Instant::now() >= deadline {
                        return Ok(O::TooLarge);
                    }
                    let is_after = match after {
                        Some(SourceArchivePosition::Revision { revision: previous }) => {
                            revision > previous
                        }
                        _ => true,
                    };
                    if is_after && selected.len() <= usize::from(limit) {
                        selected.push(revision.clone());
                    }
                }
                if selected.len() > usize::from(limit) {
                    selected.truncate(usize::from(limit));
                    context.page.next = selected
                        .last()
                        .cloned()
                        .map(|revision| SourceArchivePosition::Revision { revision });
                }
                context.page.state = HumanContentState::Ready;
                context.page.matching_count = Some(source.revisions.len() as u64);
                context.page.entries = SourceArchiveMetadataEntries::Revisions {
                    revisions: selected,
                };
            }
            SourceArchiveQuery::Records {
                source_instance_id,
                source_revision,
                ..
            } => {
                let Some(known) =
                    evertrace_domain::evidence::SourceInstanceId::parse(source_instance_id.clone())
                        .ok()
                        .and_then(|id| {
                            self.source_ranges
                                .get(&source_revision_ref(&id, source_revision))
                        })
                else {
                    return Ok(O::Page(Box::new(context)));
                };
                if let Some(SourceArchivePosition::Record { sequence, receipt }) = after
                    && !known
                        .receipt_ids
                        .get(sequence)
                        .is_some_and(|ids| ids.contains(receipt))
                {
                    return Err(StoreError::InvalidInput);
                }
                let mut records = Vec::new();
                let mut count = 0_u64;
                let mut scopes = BTreeMap::new();
                let lookup = CandidateSourceLookup::Current {
                    observations: &self.source_observations,
                    receipts: &self.source_receipts,
                    surfaces: &self.evidence_surfaces,
                };
                for (sequence, ids) in &known.receipt_ids {
                    check()?;
                    if std::time::Instant::now() >= deadline {
                        return Ok(O::TooLarge);
                    }
                    if !query.includes(*sequence) {
                        continue;
                    }
                    for id in ids {
                        check()?;
                        if std::time::Instant::now() >= deadline {
                            return Ok(O::TooLarge);
                        }
                        let (receipt, receipt_seq) = self
                            .source_receipts
                            .get(id)
                            .ok_or(StoreError::StoreCorrupt)?;
                        let (observation, seq) = self
                            .source_observations
                            .get(&receipt.source_observation_id)
                            .ok_or(StoreError::StoreCorrupt)?;
                        if receipt.source_instance_id.as_str() != source_instance_id
                            || &receipt.source_revision != source_revision
                            || receipt.source_sequence != *sequence
                            || observation.source_receipt_ref != *id
                            || observation.source_instance_id != receipt.source_instance_id
                            || observation.source_revision != receipt.source_revision
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        if self
                            .capture_product_rows(vec![source_observation_row(
                                observation.as_ref(),
                                *seq,
                            )?])?
                            .is_empty()
                        {
                            continue;
                        }
                        count = count.checked_add(1).ok_or(StoreError::StoreCorrupt)?;
                        // Resolve the same typed repository/task/worktree scope references without serializing protected text.
                        let reference = evidence_object_row_fields(
                            source_receipt_parts(receipt.as_ref()).0,
                            *receipt_seq,
                        );
                        let key = (
                            reference.repository_id.clone(),
                            reference.task_id.clone(),
                            reference.worktree_id.clone(),
                        );
                        scopes.entry(key).or_insert(reference);
                        if scopes.len() >= READ_DEPENDENCY_LIMIT {
                            return Ok(O::TooLarge);
                        }
                        // Exact matching_count is also protected: an off-page suppression cannot leak through the total.
                        if self.deletions.events().next().is_some()
                            && let Some((surface, seq)) =
                                self.evidence_surfaces.get(&receipt.source_observation_id)
                            && !self
                                .capture_product_rows(vec![surface_row(
                                    receipt.source_observation_id,
                                    surface.as_ref(),
                                    *seq,
                                )?])?
                                .is_empty()
                        {
                            context.suppressed |= source_suppressed(
                                self.deletions.events(),
                                lookup
                                    .suppression_refs(receipt.source_observation_id)?
                                    .as_ref(),
                            );
                        }
                        let is_after = match after {
                            Some(SourceArchivePosition::Record {
                                sequence: previous,
                                receipt,
                            }) => (sequence, id) > (previous, receipt),
                            _ => true,
                        };
                        if !is_after || records.len() > usize::from(limit) {
                            continue;
                        }
                        let presentation = match &receipt.protected_presentation {
                            Some(evertrace_domain::evidence::ProtectedPresentation::Inline {
                                ..
                            }) => SourceRecordPresentation::Inline,
                            Some(evertrace_domain::evidence::ProtectedPresentation::Preview {
                                ..
                            }) => SourceRecordPresentation::Preview,
                            Some(
                                evertrace_domain::evidence::ProtectedPresentation::Unavailable {
                                    ..
                                },
                            ) => SourceRecordPresentation::NonText,
                            None => SourceRecordPresentation::NotRecorded,
                        };
                        records.push(SourceRecordMetadata {
                            stable_key: format!(
                                "object:evidence:source_observation:{}",
                                observation.source_observation_id
                            ),
                            observation_id: observation.source_observation_id,
                            receipt_id: *id,
                            record_identity: receipt.source_record_identity.clone(),
                            sequence: *sequence,
                            byte_range: receipt.source_byte_range.clone(),
                            observation_role: receipt.observation_role,
                            source_role: observation.source_role,
                            content_trust: observation.content_trust,
                            completeness: receipt.capture_completeness,
                            archive_mode: receipt.archive_mode,
                            event_time_us: receipt.event_time_us,
                            recorded_at_us: receipt.recorded_at_us,
                            event_time_provenance: receipt.event_time_provenance,
                            presentation,
                        });
                    }
                }
                if records.len() > usize::from(limit) {
                    records.truncate(usize::from(limit));
                    context.page.next =
                        records.last().map(|record| SourceArchivePosition::Record {
                            sequence: record.sequence,
                            receipt: record.receipt_id,
                        });
                }
                // An empty interval is still source data: preserve the original first-record authorization witness.
                if scopes.is_empty() {
                    let Some(id) = known.receipt_ids.values().find_map(|ids| ids.first()) else {
                        return Ok(O::Page(Box::new(context)));
                    };
                    let (receipt, receipt_seq) = self
                        .source_receipts
                        .get(id)
                        .ok_or(StoreError::StoreCorrupt)?;
                    let (observation, seq) = self
                        .source_observations
                        .get(&receipt.source_observation_id)
                        .ok_or(StoreError::StoreCorrupt)?;
                    if self
                        .capture_product_rows(vec![source_observation_row(
                            observation.as_ref(),
                            *seq,
                        )?])?
                        .is_empty()
                    {
                        return Ok(O::Page(Box::new(context)));
                    }
                    let reference = evidence_object_row_fields(
                        source_receipt_parts(receipt.as_ref()).0,
                        *receipt_seq,
                    );
                    let key = (
                        reference.repository_id.clone(),
                        reference.task_id.clone(),
                        reference.worktree_id.clone(),
                    );
                    scopes.insert(key, reference);
                    if self.deletions.events().next().is_some()
                        && let Some((surface, seq)) =
                            self.evidence_surfaces.get(&receipt.source_observation_id)
                        && !self
                            .capture_product_rows(vec![surface_row(
                                receipt.source_observation_id,
                                surface.as_ref(),
                                *seq,
                            )?])?
                            .is_empty()
                    {
                        context.suppressed |= source_suppressed(
                            self.deletions.events(),
                            lookup
                                .suppression_refs(receipt.source_observation_id)?
                                .as_ref(),
                        );
                    }
                }
                let mut scope_rows = BTreeMap::new();
                let mut scope_bytes = 0_u64;
                let mut insert_scope = |row: ObjectRow| {
                    if scope_rows.contains_key(&row.row_id) {
                        return true;
                    }
                    scope_bytes += row.payload_json.as_ref().map_or(0, |value| value.len()) as u64;
                    if scope_bytes > READ_DEPENDENCY_BYTES {
                        return false;
                    }
                    scope_rows.insert(row.row_id.clone(), row);
                    true
                };
                for reference in scopes.values() {
                    check()?;
                    if std::time::Instant::now() >= deadline {
                        return Ok(O::TooLarge);
                    }
                    if let Some(id) = &reference.task_id {
                        let (task, seq) = self
                            .tasks
                            .get(&id.parse().map_err(|_| StoreError::StoreCorrupt)?)
                            .ok_or(StoreError::StoreCorrupt)?;
                        let row = self
                            .scope_fact_row(
                                &JournalPayload::TaskRecorded(Box::new(task.clone())),
                                *seq,
                            )?
                            .ok_or(StoreError::StoreCorrupt)?;
                        if !insert_scope(row) {
                            return Ok(O::TooLarge);
                        }
                    }
                    if let Some(id) = &reference.worktree_id {
                        let (tree, seq) = self
                            .worktrees
                            .get(&id.parse().map_err(|_| StoreError::StoreCorrupt)?)
                            .ok_or(StoreError::StoreCorrupt)?;
                        let row = self
                            .scope_fact_row(
                                &JournalPayload::WorktreeInstanceRecorded(Box::new(tree.clone())),
                                *seq,
                            )?
                            .ok_or(StoreError::StoreCorrupt)?;
                        if !insert_scope(row) {
                            return Ok(O::TooLarge);
                        }
                    }
                }
                context.scope_rows = scope_rows.into_values().collect();
                context.references = scopes.into_values().collect();
                context.page.state = HumanContentState::Ready;
                context.page.matching_count = Some(count);
                context.page.entries = SourceArchiveMetadataEntries::Records { records };
            }
        }
        Ok(O::Page(Box::new(context)))
    }

    pub(crate) fn source_archive_context(
        &self,
        query: &SourceArchiveQuery,
        after: Option<&SourceArchiveCursor>,
        limit: usize,
        has_failed_job: bool,
    ) -> Result<SourceArchiveCurrentContext, StoreError> {
        use std::ops::Bound::{Excluded, Included, Unbounded};
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if !(1..=32).contains(&limit) || after.is_some_and(|cursor| !cursor.validate_for(query)) {
            return Err(StoreError::InvalidInput);
        }
        // Retained watermark identities do not bypass the canonical product
        // deletion/repository closure that hides their owning catalogue source.
        let visible = self.source_catalog_contains(query.source())?;
        if !visible {
            return Ok(match query {
                SourceArchiveQuery::Revisions { .. } => {
                    SourceArchiveCurrentContext::Revisions(SourceArchivePage {
                        frontier: self.frontier,
                        query: query.clone(),
                        state: HumanContentState::Missing,
                        entries: SourceArchiveEntries::Revisions {
                            revisions: Vec::new(),
                        },
                        next_cursor: None,
                    })
                }
                SourceArchiveQuery::Records { .. } => SourceArchiveCurrentContext::Records {
                    found: false,
                    authorization: None,
                    context: CaptureCurrentContext {
                        frontier: self.frontier,
                        has_failed_job,
                        items: Vec::new(),
                        next_cursor: None,
                    },
                },
            });
        }
        match query {
            SourceArchiveQuery::Revisions { source_instance_id } => {
                let source = self.source_watermarks.get(source_instance_id);
                if let Some(cursor) = after
                    && cursor.frontier == self.frontier
                {
                    let SourceArchivePosition::Revision { revision } = &cursor.position else {
                        return Err(StoreError::InvalidInput);
                    };
                    if !source.is_some_and(|source| source.revisions.contains_key(revision)) {
                        return Err(StoreError::InvalidInput);
                    }
                }
                let start = match after.map(|cursor| &cursor.position) {
                    Some(SourceArchivePosition::Revision { revision }) => {
                        Excluded(revision.clone())
                    }
                    _ => Unbounded,
                };
                let mut revisions = Vec::with_capacity(limit);
                let mut next_cursor = None;
                if let Some(source) = source {
                    for (revision, _) in source.revisions.range((start, Unbounded)) {
                        if revisions.len() == limit {
                            next_cursor = Some(
                                serde_json::to_string(&SourceArchiveCursor {
                                    frontier: self.frontier,
                                    query: query.clone(),
                                    position: SourceArchivePosition::Revision {
                                        revision: revisions
                                            .last()
                                            .cloned()
                                            .ok_or(StoreError::StoreCorrupt)?,
                                    },
                                })
                                .map_err(|_| StoreError::StoreCorrupt)?,
                            );
                            break;
                        }
                        revisions.push(revision.clone());
                    }
                }
                Ok(SourceArchiveCurrentContext::Revisions(SourceArchivePage {
                    frontier: self.frontier,
                    query: query.clone(),
                    state: if source.is_some() {
                        HumanContentState::Ready
                    } else {
                        HumanContentState::Missing
                    },
                    entries: SourceArchiveEntries::Revisions { revisions },
                    next_cursor,
                }))
            }
            SourceArchiveQuery::Records {
                source_instance_id,
                source_revision,
                from_sequence,
                ..
            } => {
                let known =
                    evertrace_domain::evidence::SourceInstanceId::parse(source_instance_id.clone())
                        .ok()
                        .and_then(|instance| {
                            self.source_ranges
                                .get(&source_revision_ref(&instance, source_revision))
                        });
                if let Some(cursor) = after
                    && cursor.frontier == self.frontier
                {
                    let SourceArchivePosition::Record { sequence, receipt } = &cursor.position
                    else {
                        return Err(StoreError::InvalidInput);
                    };
                    if !known.is_some_and(|known| {
                        known
                            .receipt_ids
                            .get(sequence)
                            .is_some_and(|ids| ids.contains(receipt))
                    }) {
                        return Err(StoreError::InvalidInput);
                    }
                }
                let mut selected = Vec::with_capacity(limit);
                let mut last_position = None;
                let mut next_cursor = None;
                let start = match after.map(|cursor| &cursor.position) {
                    Some(SourceArchivePosition::Record { sequence, .. }) => Included(*sequence),
                    _ => from_sequence.map_or(Unbounded, Included),
                };
                if let Some(known) = known {
                    'records: for (sequence, ids) in known.receipt_ids.range((start, Unbounded)) {
                        if !query.includes(*sequence) {
                            break;
                        }
                        for id in ids {
                            if matches!(after.map(|cursor|&cursor.position),Some(SourceArchivePosition::Record{sequence:old,receipt}) if sequence==old && id<=receipt)
                            {
                                continue;
                            }
                            let (receipt, _) = self
                                .source_receipts
                                .get(id)
                                .ok_or(StoreError::StoreCorrupt)?;
                            if receipt.source_instance_id.as_str() != source_instance_id
                                || &receipt.source_revision != source_revision
                                || receipt.source_sequence != *sequence
                            {
                                return Err(StoreError::StoreCorrupt);
                            }
                            let (observation, seq) = self
                                .source_observations
                                .get(&receipt.source_observation_id)
                                .ok_or(StoreError::StoreCorrupt)?;
                            if observation.source_receipt_ref != *id {
                                return Err(StoreError::StoreCorrupt);
                            }
                            let rows = self.capture_product_rows(vec![source_observation_row(
                                observation.as_ref(),
                                *seq,
                            )?])?;
                            if let Some(row) = rows.into_iter().next() {
                                if selected.len() == limit {
                                    next_cursor = Some(
                                        serde_json::to_string(&SourceArchiveCursor {
                                            frontier: self.frontier,
                                            query: query.clone(),
                                            position: last_position
                                                .clone()
                                                .ok_or(StoreError::StoreCorrupt)?,
                                        })
                                        .map_err(|_| StoreError::StoreCorrupt)?,
                                    );
                                    break 'records;
                                }
                                selected.push((row, receipt.source_observation_id));
                                last_position = Some(SourceArchivePosition::Record {
                                    sequence: *sequence,
                                    receipt: *id,
                                });
                            }
                        }
                    }
                }
                let authorization = if selected.is_empty() {
                    known
                        .and_then(|known| known.receipt_ids.values().find_map(|ids| ids.first()))
                        .map(|id| {
                            let (receipt, _) = self
                                .source_receipts
                                .get(id)
                                .ok_or(StoreError::StoreCorrupt)?;
                            let (observation, seq) = self
                                .source_observations
                                .get(&receipt.source_observation_id)
                                .ok_or(StoreError::StoreCorrupt)?;
                            let rows = self.capture_product_rows(vec![source_observation_row(
                                observation.as_ref(),
                                *seq,
                            )?])?;
                            let selected = rows
                                .into_iter()
                                .map(|row| (row, receipt.source_observation_id))
                                .collect();
                            Ok(self.capture_selected_items(selected, false)?.pop())
                        })
                        .transpose()?
                        .flatten()
                        .map(Box::new)
                } else {
                    None
                };
                Ok(SourceArchiveCurrentContext::Records {
                    found: known.is_some(),
                    authorization,
                    context: CaptureCurrentContext {
                        frontier: self.frontier,
                        has_failed_job,
                        items: self.capture_selected_items(selected, false)?,
                        next_cursor,
                    },
                })
            }
        }
    }
}
