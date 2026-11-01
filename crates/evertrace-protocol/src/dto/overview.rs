use super::*;
use evertrace_domain::query::{
    MemoryOverviewCount, MemoryOverviewGeneration, MemoryOverviewQuery, MemoryTimeBasis,
    OverviewCountBasis, OverviewCountUnit,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanMemoryOverviewPage {
    pub frontier: u64,
    pub observed_at_us: i64,
    pub query: MemoryOverviewQuery,
    pub scope_available: bool,
    pub complete: bool,
    pub summaries: Vec<HumanSnapshotItem>,
    pub changes: Vec<HumanSnapshotItem>,
    pub unresolved: Vec<HumanSnapshotItem>,
    pub reviews: Vec<HumanSnapshotItem>,
    pub summary_count: MemoryOverviewCount,
    pub formal_count: MemoryOverviewCount,
    pub loop_count: MemoryOverviewCount,
    pub review_count: MemoryOverviewCount,
    pub review_reasons:
        std::collections::BTreeMap<String, evertrace_domain::query::InboxReviewReason>,
    pub generation: MemoryOverviewGeneration,
}

impl HumanMemoryOverviewPage {
    pub fn validate(&self) -> bool {
        let valid_count = |count: &MemoryOverviewCount, unit| {
            count.unit == unit
                && matches!(
                    (count.count, count.basis),
                    (None, OverviewCountBasis::Unknown)
                        | (
                            Some(_),
                            OverviewCountBasis::Exact | OverviewCountBasis::LowerBound
                        )
                )
        };
        let sections = [
            (
                &self.summaries,
                &self.summary_count,
                Some(&["semantic_digest"][..]),
            ),
            (
                &self.changes,
                &self.formal_count,
                Some(&["atom_revision", "procedure_revision", "core_membership"][..]),
            ),
            (
                &self.unresolved,
                &self.loop_count,
                Some(&["work_episode"][..]),
            ),
            (&self.reviews, &self.review_count, None),
        ];
        self.query.validate().is_ok()
            && self.observed_at_us >= 0
            && valid_count(
                &self.summary_count,
                OverviewCountUnit::CurrentSummaryRevisions,
            )
            && valid_count(
                &self.formal_count,
                OverviewCountUnit::CurrentFormalRevisions,
            )
            && valid_count(&self.loop_count, OverviewCountUnit::OpenLoopEntries)
            && valid_count(&self.review_count, OverviewCountUnit::PendingReviewItems)
            && self.review_reasons.len() == self.reviews.len()
            && self.reviews.iter().all(|item| {
                self.review_reasons
                    .get(&item.stable_key)
                    .is_some_and(|reason| {
                        reason.object_kind() == item.object_kind
                            && match reason {
                                evertrace_domain::query::InboxReviewReason::Proposal {
                                    status,
                                    eligibility,
                                } => item.proposal.as_ref().is_some_and(|proposal| {
                                    proposal.status == *status
                                        && proposal.eligibility == *eligibility
                                        && matches!(
                                        status,
                                        evertrace_domain::semantic::ProposalStatus::Pending
                                            | evertrace_domain::semantic::ProposalStatus::Validating
                                            | evertrace_domain::semantic::ProposalStatus::Deferred
                                    )
                                }),
                                _ => item.proposal.is_none(),
                            }
                    })
            })
            && (!self.complete || self.scope_available)
            && sections.iter().all(|(items, count, kinds)| {
                items.len() <= usize::from(self.query.limit)
                    && count.count.is_none_or(|value| value >= items.len() as u64)
                    && items.iter().all(|item| {
                        item.validate()
                            && kinds.is_none_or(|kinds| kinds.contains(&item.object_kind.as_str()))
                            && item.source_event_seq <= self.frontier
                            && self.rank(item).is_some()
                            && (!self.complete
                                || item.reading_preview.as_ref().map_or_else(
                                    || {
                                        self.review_reasons
                                            .get(&item.stable_key)
                                            .is_some_and(|reason| reason.is_metadata_only())
                                    },
                                    |preview| preview.state == HumanContentState::Ready,
                                ))
                    })
                    && items
                        .iter()
                        .map(|item| &item.stable_key)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == items.len()
                    && items.windows(2).all(|pair| {
                        self.rank(&pair[0])
                            .zip(self.rank(&pair[1]))
                            .is_some_and(|(left, right)| left < right)
                    })
            })
            && (self.scope_available
                || (sections.iter().all(|(items, _, _)| items.is_empty())
                    && [
                        &self.summary_count,
                        &self.formal_count,
                        &self.loop_count,
                        &self.review_count,
                    ]
                    .iter()
                    .all(|count| count.count.is_none())))
    }

    fn rank(&self, item: &HumanSnapshotItem) -> Option<(i128, i128, String)> {
        let event = self
            .query
            .time_range
            .as_ref()
            .is_some_and(|range| range.basis == MemoryTimeBasis::Event);
        let clock = if event {
            i128::from(item.native_event_time_us?)
        } else {
            0
        };
        if let Some(range) = &self.query.time_range
            && event
            && !range.contains(item.native_event_time_us?, 0)
        {
            return None;
        }
        Some((
            -clock,
            -i128::from(item.source_event_seq),
            item.stable_key.clone(),
        ))
    }
}
