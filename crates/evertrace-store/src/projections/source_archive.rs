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
impl JournalAdmissionState {
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
        let visible = !self
            .source_catalog_page(
                &SourceCatalogQuery {
                    source_instance_id: Some(query.source().to_owned()),
                    ..Default::default()
                },
                None,
                1,
            )?
            .entries
            .is_empty();
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
