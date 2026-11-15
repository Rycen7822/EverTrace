//! Source-local archive reads over the existing rebuildable receipt/watermark index.
use super::*;
use evertrace_domain::{query::HumanContentState, source::*};

/// Native-only authorization inputs; source receipt text/payloads never enter a metadata batch.
#[derive(Debug)]
pub struct SourceArchiveMetadataContext {
    pub page: SourceArchiveMetadataPage,
    pub scope_rows: Vec<ObjectRow>,
    pub references: Vec<ObjectRow>,
}

impl JournalAdmissionState {
    fn source_archive_progress(
        &self,
        current: &crate::SessionImportCurrent,
        instance: &SourceInstanceId,
        revision: &SourceRevision,
    ) -> SourceArchiveProgress {
        let metadata = &current.metadata;
        let selected_current = &metadata.source_revision == revision;
        let watermark = self
            .source_watermarks
            .get(instance.as_str())
            .and_then(|state| state.revisions.get(revision));
        let earlier = watermark.and_then(|value| value.earlier_prefix.as_ref());
        let origin = metadata
            .prospective_origin
            .as_ref()
            .filter(|_| selected_current);
        SourceArchiveProgress {
            catalog_source_revision: metadata.source_revision.clone(),
            observed_file_bytes: selected_current.then_some(metadata.file_size),
            metadata_state: selected_current.then_some(metadata.metadata_state),
            body_state: selected_current.then_some(current.body_state),
            observed_end: origin.map(|value| value.observed_end),
            record_start: origin.and_then(|value| value.record_start),
            origin_closed: origin.map(|value| value.closed),
            confirmed_through: watermark.map(|value| value.source_sequence),
            earlier_fence: earlier.map(|value| value.fence_byte),
            earlier_through: earlier.map(|value| value.through_byte),
            forward_commitment: watermark
                .is_some_and(|value| value.confirmed_prefix_digest.is_some()),
            earlier_commitment: earlier.is_some_and(|value| value.digest.is_some()),
            replacement_recorded: self
                .source_watermarks
                .get(instance.as_str())
                .is_some_and(|state| state.revision_admissions.contains_key(revision)),
        }
    }

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
                progress: None,
                matching_count: None,
                next: None,
            },
            scope_rows: Vec::new(),
            references: Vec::new(),
        };
        let check = || {
            if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                Err(StoreError::Io)
            } else {
                Ok(())
            }
        };
        check()?;
        let Some(current) = self.source_catalog_current(query.source())? else {
            return Ok(O::Page(Box::new(context)));
        };
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
                let instance = SourceInstanceId::parse(source_instance_id.clone())
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let Some(known) = self
                    .source_ranges
                    .get(&source_revision_ref(&instance, source_revision))
                else {
                    return Ok(O::Page(Box::new(context)));
                };
                context.page.progress =
                    Some(self.source_archive_progress(current, &instance, source_revision));
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
                        records.push(
                            SourceRecordMetadata::from_records(
                                receipt.as_ref(),
                                observation.as_ref(),
                                source_suppressed(
                                    self.deletions.events(),
                                    lookup
                                        .suppression_refs(receipt.source_observation_id)?
                                        .as_ref(),
                                ),
                            )
                            .ok_or(StoreError::StoreCorrupt)?,
                        );
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
}
