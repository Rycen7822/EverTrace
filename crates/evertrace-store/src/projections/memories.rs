//! Request-local human metadata browsing over the canonical admission indexes.
use super::*;
use evertrace_domain::query::{
    MemoryBrowseCursor, MemoryBrowseOrder, MemoryBrowseQuery, MemoryReadingKind,
};

#[derive(Debug)]
pub struct MemoryBrowseContext {
    pub page: MemoriesCurrentContext,
    /// Current metadata records; body access remains an independent decision.
    pub total_count: u64,
    pub matching_count: u64,
}

impl JournalAdmissionState {
    pub(crate) fn memory_browse_context(
        &self,
        query: &MemoryBrowseQuery,
        after: Option<&MemoryBrowseCursor>,
        limit: usize,
        has_failed_job: bool,
    ) -> Result<MemoryBrowseContext, StoreError> {
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if after.is_some_and(|cursor| cursor.validate_for(query).is_err()) {
            return Err(StoreError::InvalidInput);
        }
        if limit == 0 || limit > 64 {
            return Err(StoreError::InvalidInput);
        }
        let ProductDeletionIds {
            revision_ids: revisions,
            atom_ids: atoms,
            procedure_ids: procedures,
            membership_ids: memberships,
        } = product_deletion_ids(&self.deletions);
        let contracts = self.s23.deletion_owned_contracts(&revisions, &memberships);
        // No corpus clone or Web index: consume one current record at a time
        // and retain only the selected limit+1. Historical reads stay separate.
        let rows = self
            .atoms
            .values()
            .filter(|(value, _)| {
                !atoms.contains(&value.atom_id) && !revisions.contains(&value.revision_id)
            })
            .map(|(value, seq)| {
                let mut row = semantic_atom_row(
                    value,
                    &JournalPayload::AtomRecorded(Box::new(value.clone())),
                    *seq,
                )?;
                row.support_state = self
                    .s23
                    .atom_support_state_excluding(value.revision_id, &contracts)
                    .map(str::to_owned);
                Ok(row)
            })
            .chain(
                self.s23
                    .all_membership_revisions()
                    .filter(|value| {
                        !revisions.contains(&value.membership_revision_id)
                            && !memberships.contains(&value.core_membership_id)
                            && self
                                .s23
                                .current_membership(value.core_membership_id)
                                .is_some_and(|current| {
                                    current.membership_revision_id == value.membership_revision_id
                                })
                    })
                    .map(|value| {
                        self.s23
                            .membership_row(value.membership_revision_id, PROJECTION_GENERATION)
                    }),
            )
            .chain(
                self.procedure
                    .all_revisions()
                    .filter(|value| {
                        !revisions.contains(&value.revision_id)
                            && self.procedure.is_current_revision_id(value.revision_id)
                    })
                    .map(|value| {
                        self.procedure.revision_row(
                            value.revision_id,
                            PROJECTION_GENERATION,
                            self.s23
                                .successor_support_state_excluding(value.revision_id, &contracts),
                        )
                    }),
            )
            .chain(
                self.proposals
                    .values()
                    .filter(|(value, _)| {
                        !revisions.contains(&value.proposal_revision_id)
                            && !value
                                .base_revision_id
                                .is_some_and(|id| revisions.contains(&id))
                            && !proposal_targets_deleted(value, &atoms, &procedures, &memberships)
                            && (revisions.is_empty()
                                || !self.proposal_revisions.values().any(|(candidate, _)| {
                                    candidate.proposal_id == value.proposal_id
                                        && proposal_targets_deleted(
                                            candidate,
                                            &atoms,
                                            &procedures,
                                            &memberships,
                                        )
                                }))
                    })
                    .map(|(value, seq)| {
                        semantic_proposal_row(
                            value,
                            &JournalPayload::RevisionProposalRecorded(Box::new(value.clone())),
                            *seq,
                        )
                    }),
            )
            .chain(self.synthesis.digests().values().map(|(value, seq)| {
                synthesis::digest_row(value.semantic_digest_id, value.clone(), *seq)
            }));
        let rank = |seq: u64, key: &str| {
            (
                match query.order {
                    MemoryBrowseOrder::RecordedNewest => u64::MAX - seq,
                    MemoryBrowseOrder::RecordedOldest => seq,
                },
                key.to_owned(),
            )
        };
        let after_rank = after.map(|value| rank(value.source_event_seq, &value.row_id));
        let mut selected = BTreeMap::new();
        let (mut total_count, mut matching_count) = (0_u64, 0_u64);
        for row in rows {
            for row in filter_product_rows(
                vec![row?],
                &self.deletions,
                &self.scope_purges,
                self.repository_closures.values(),
            )? {
                total_count += 1;
                let kind = match row.object_kind.as_deref() {
                    Some("semantic_digest") => MemoryReadingKind::Summaries,
                    Some("atom_revision" | "core_membership") => {
                        MemoryReadingKind::FactsAndConstraints
                    }
                    Some("procedure_revision") => MemoryReadingKind::Methods,
                    Some("revision_proposal_revision") => MemoryReadingKind::References,
                    _ => return Err(StoreError::StoreCorrupt),
                };
                if (query.kind != MemoryReadingKind::All && query.kind != kind)
                    || query
                        .epistemic_status
                        .is_some_and(|value| row.epistemic.as_deref() != Some(value.as_str()))
                    || query
                        .authority
                        .is_some_and(|value| row.authority.as_deref() != Some(value.as_str()))
                    || query
                        .atom_lifecycle
                        .is_some_and(|value| row.lifecycle.as_deref() != Some(value.as_str()))
                {
                    continue;
                }
                matching_count += 1;
                let position = rank(row.source_event_seq, &row.row_id);
                if after_rank.as_ref().is_some_and(|after| position <= *after) {
                    continue;
                }
                selected.insert(position, row);
                if selected.len() > limit + 1 {
                    selected.pop_last();
                }
            }
        }
        let mut items = selected.into_values().collect::<Vec<_>>();
        let next_cursor = if items.len() > limit {
            let last = &items[limit - 1];
            Some(
                serde_json::to_string(&MemoryBrowseCursor {
                    frontier: self.frontier,
                    query: query.clone(),
                    source_event_seq: last.source_event_seq,
                    row_id: last.row_id.clone(),
                })
                .map_err(|_| StoreError::StoreCorrupt)?,
            )
        } else {
            None
        };
        items.truncate(limit);
        let current_proposal_revisions = items
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("revision_proposal_revision"))
            .filter_map(|row| row.object_id.as_deref()?.parse::<RevisionProposalId>().ok())
            .filter_map(|id| {
                self.proposals
                    .get(&id)
                    .map(|(value, _)| value.proposal_revision_id)
            })
            .collect();
        Ok(MemoryBrowseContext {
            page: MemoriesCurrentContext {
                frontier: self.frontier,
                has_failed_job,
                items,
                current_proposal_revisions,
                next_cursor,
            },
            total_count,
            matching_count,
        })
    }
}
