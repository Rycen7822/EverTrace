//! A read-only composition of scoped Native observations, not a generation request.
use super::*;
use crate::WriterActorError;
use evertrace_domain::query::{
    MemoryOverviewCount, MemoryOverviewGeneration, MemoryOverviewQuery, OverviewCountBasis,
    OverviewCountUnit, SummaryGenerationObservation as Observation, SummaryGenerationRecord,
};

#[derive(Clone, Copy)]
pub(super) struct SummaryPolicy {
    llm_enabled: bool,
    episode_enrichment: bool,
}

pub struct HumanMemoryOverviewPage {
    pub frontier: u64,
    pub observed_at_us: i64,
    pub query: MemoryOverviewQuery,
    pub scope_available: bool,
    pub complete: bool,
    pub summaries: Vec<HumanSummary>,
    pub changes: Vec<HumanSummary>,
    pub unresolved: Vec<HumanSummary>,
    pub reviews: Vec<HumanSummary>,
    pub summary_count: MemoryOverviewCount,
    pub formal_count: MemoryOverviewCount,
    pub loop_count: MemoryOverviewCount,
    pub review_count: MemoryOverviewCount,
    pub generation: MemoryOverviewGeneration,
}

fn count(value: Option<u64>, complete: bool, unit: OverviewCountUnit) -> MemoryOverviewCount {
    MemoryOverviewCount {
        count: value,
        unit,
        basis: match value {
            None => OverviewCountBasis::Unknown,
            Some(_) if complete => OverviewCountBasis::Exact,
            Some(_) => OverviewCountBasis::LowerBound,
        },
    }
}

struct Section {
    items: Vec<HumanSummary>,
    count: Option<u64>,
    complete: bool,
    available: bool,
}

fn section(context: evertrace_store::MemoryBrowseContext) -> Result<Section, HumanGovernanceError> {
    let mut page = memories_page(context.page)?;
    for item in &mut page.items {
        item.native_event_time_us = context.event_times.get(&item.source_event_seq).copied();
    }
    Ok(Section {
        items: page.items,
        count: context.matching_count,
        complete: context.counts_complete,
        available: context.scope_available,
    })
}

impl HumanGovernanceService {
    pub fn with_summary_policy(mut self, llm: &evertrace_domain::config::LlmConfig) -> Self {
        self.summary_policy = Some(SummaryPolicy {
            llm_enabled: llm.enabled,
            episode_enrichment: llm.episode_enrichment
                != evertrace_domain::config::EpisodeEnrichment::Off,
        });
        self
    }

    pub async fn memory_overview(
        &self,
        query: MemoryOverviewQuery,
        expected_frontier: Option<u64>,
    ) -> Result<Result<HumanMemoryOverviewPage, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let context =
            self.writer
                .memory_overview_context(&query)
                .await
                .map_err(|error| match error {
                    WriterActorError::InvalidInput => HumanGovernanceError::InvalidInput,
                    _ => HumanGovernanceError::Store,
                })?;
        if expected_frontier.is_some_and(|expected| expected != context.frontier) {
            return Ok(Err(context.frontier));
        }
        let summaries = section(context.summaries)?;
        let facts = section(context.facts)?;
        let methods = section(context.methods)?;
        let reviews = section(context.reviews)?;
        let scope_available = summaries.available
            && facts.available
            && methods.available
            && reviews.available
            && context.work.scope_available;
        let metadata_complete = summaries.complete
            && facts.complete
            && methods.complete
            && reviews.complete
            && context.work.complete;
        let formal_count = match (facts.count, methods.count) {
            (Some(a), Some(b)) => Some(a.checked_add(b).ok_or(HumanGovernanceError::Store)?),
            _ => None,
        };
        let mut changes = facts.items;
        changes.extend(methods.items);
        let mut keyed = Vec::with_capacity(changes.len());
        let event_order = query
            .time_range
            .as_ref()
            .is_some_and(|range| range.basis == evertrace_domain::query::MemoryTimeBasis::Event);
        for item in changes {
            let clock = if event_order {
                i128::from(
                    item.native_event_time_us
                        .ok_or(HumanGovernanceError::Store)?,
                )
            } else {
                0
            };
            keyed.push((
                (
                    -clock,
                    -i128::from(item.source_event_seq),
                    item.stable_key.clone(),
                ),
                item,
            ));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        let changes = keyed
            .into_iter()
            .take(usize::from(query.limit))
            .map(|(_, item)| item)
            .collect::<Vec<_>>();
        let work_page = evertrace_store::MemoriesCurrentContext {
            frontier: context.frontier,
            has_failed_job: false,
            items: context.work.episodes,
            current_proposal_revisions: Default::default(),
            next_cursor: None,
        };
        let mut unresolved = memories_page(work_page)?.items;
        for item in &mut unresolved {
            item.native_event_time_us = context
                .work
                .event_times
                .get(&item.source_event_seq)
                .copied();
        }
        let sizes = [
            summaries.items.len(),
            changes.len(),
            unresolved.len(),
            reviews.items.len(),
        ];
        let mut items = summaries.items;
        items.extend(changes);
        items.extend(unresolved);
        items.extend(reviews.items);
        // One permission-checked preview read for the selected rows, not a browser mirror.
        self.reading_previews(&mut items).await;
        let complete = scope_available
            && metadata_complete
            && items.iter().all(|item| {
                item.reading_preview
                    .as_ref()
                    .is_some_and(|preview| preview.state == HumanContentState::Ready)
            });
        let mut items = items.into_iter();
        let mut observations = Vec::new();
        let config = self.summary_policy.as_ref();
        if summaries.count.is_none_or(|count| count == 0) {
            if context.work.no_inputs && complete {
                observations.push(Observation::NoInputs);
            }
            if config.is_some_and(|snapshot| !snapshot.llm_enabled) {
                observations.push(Observation::LlmDisabled);
            }
            if config.is_some_and(|snapshot| !snapshot.episode_enrichment) {
                observations.push(Observation::EpisodeEnrichmentDisabled);
            }
            if context.work.open_work_count > 0 {
                observations.push(Observation::WorkInProgress);
            }
            if let Some(run) = &context.work.last_run
                && self.effective_config_hash == run.effective_config_hash
            {
                use evertrace_domain::semantic::DerivationRunStatus as Status;
                match run.status {
                    Status::BudgetExhausted => {
                        observations.push(Observation::LastAttemptBudgetExhausted)
                    }
                    Status::ProviderUnavailable | Status::ProviderFailed => {
                        observations.push(Observation::LastAttemptProviderUnavailable)
                    }
                    _ => {}
                }
            }
            if observations.is_empty() || !metadata_complete || summaries.count.is_none() {
                observations.push(Observation::NotRead);
            }
        }
        let generation = MemoryOverviewGeneration {
            observations,
            llm_enabled: config.map(|snapshot| snapshot.llm_enabled),
            episode_enrichment_enabled: config.map(|snapshot| snapshot.episode_enrichment),
            last_run: context.work.last_run.map(|run| SummaryGenerationRecord {
                run_id: run.run_id,
                episode_id: run.episode_id,
                input_revision_id: run.input_revision_id,
                status: run.status,
                created_at_us: run.created_at_us,
            }),
        };
        let observed_at_us = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| HumanGovernanceError::Store)?
                .as_micros(),
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        Ok(Ok(HumanMemoryOverviewPage {
            frontier: context.frontier,
            observed_at_us,
            query,
            scope_available,
            complete,
            summaries: items.by_ref().take(sizes[0]).collect(),
            changes: items.by_ref().take(sizes[1]).collect(),
            unresolved: items.by_ref().take(sizes[2]).collect(),
            reviews: items.take(sizes[3]).collect(),
            summary_count: count(
                summaries.count,
                summaries.complete,
                OverviewCountUnit::CurrentSummaryRevisions,
            ),
            formal_count: count(
                formal_count,
                facts.complete && methods.complete,
                OverviewCountUnit::CurrentFormalRevisions,
            ),
            loop_count: count(
                context
                    .work
                    .scope_available
                    .then_some(context.work.loop_count),
                context.work.complete,
                OverviewCountUnit::OpenLoopEntries,
            ),
            review_count: count(
                reviews.count,
                reviews.complete,
                OverviewCountUnit::PendingProposalRevisions,
            ),
            generation,
        }))
    }
}
