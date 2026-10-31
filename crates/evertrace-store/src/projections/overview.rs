//! Scoped current-work observations for the human memory overview.
use super::*;
use evertrace_domain::query::{MemoryOverviewQuery, MemoryTimeBasis};

pub struct MemoryOverviewContext {
    pub frontier: u64,
    pub summaries: memories::MemoryBrowseContext,
    pub facts: memories::MemoryBrowseContext,
    pub methods: memories::MemoryBrowseContext,
    pub reviews: memories::MemoryBrowseContext,
    pub work: MemoryOverviewWorkContext,
}

pub struct MemoryOverviewWorkContext {
    pub episodes: Vec<ObjectRow>,
    pub event_times: BTreeMap<u64, i64>,
    pub scope_available: bool,
    pub complete: bool,
    pub work_count: u64,
    pub open_work_count: u64,
    pub loop_count: u64,
    pub no_inputs: bool,
    pub last_run: Option<MemoryOverviewRun>,
}

pub struct MemoryOverviewRun {
    pub run_id: evertrace_domain::ids::SemanticDerivationRunId,
    pub episode_id: evertrace_domain::ids::WorkEpisodeId,
    pub input_revision_id: evertrace_domain::revision::RevisionId,
    pub status: evertrace_domain::semantic::DerivationRunStatus,
    pub effective_config_hash: [u8; 32],
    pub created_at_us: i64,
}

impl JournalAdmissionState {
    pub(crate) fn memory_overview_work_context(
        &self,
        query: &MemoryOverviewQuery,
        mut times: Option<&mut crate::sqlite_state::JournalTimeReader<'_>>,
    ) -> Result<MemoryOverviewWorkContext, StoreError> {
        use evertrace_domain::{semantic::AtomScope, work::EpisodeLifecycle};
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        let scope = self.memory_scope_context(query.selection)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut result = MemoryOverviewWorkContext {
            episodes: vec![],
            event_times: BTreeMap::new(),
            scope_available: scope.available,
            complete: scope.complete,
            work_count: 0,
            open_work_count: 0,
            loop_count: 0,
            no_inputs: self.source_observations.is_empty(),
            last_run: None,
        };
        if !scope.available {
            return Ok(result);
        }
        let mut selected = BTreeMap::new();
        let mut scoped_work = BTreeMap::new();
        for (episode, seq) in self.episodes.values() {
            if std::time::Instant::now() >= deadline {
                result.complete = false;
                break;
            }
            let mut scopes = vec![AtomScope::Task {
                task_id: episode.task_id,
            }];
            if let Some(id) = episode.repository_instance_id {
                scopes.push(AtomScope::Repository {
                    repository_instance_id: id,
                });
                if let Some(tree) = episode.worktree_instance_id {
                    scopes.push(AtomScope::Worktree {
                        repository_instance_id: id,
                        worktree_instance_id: tree,
                    });
                }
            }
            if !scope.includes(query.selection, query.include_global, Some(&scopes)) {
                continue;
            }
            if !self.scope_fact_visible(
                &JournalPayload::WorkEpisodeRecorded(Box::new(episode.clone())),
                *seq,
            )? {
                continue;
            }
            result.work_count += 1;
            result.open_work_count += u64::from(episode.lifecycle_status == EpisodeLifecycle::Open);
            scoped_work.insert(episode.episode_id, episode.source_watermark);
            if episode.open_loops.is_empty() {
                continue;
            }
            let clock = if let Some(range) = &query.time_range {
                let reader = times.as_deref_mut().ok_or(StoreError::StoreCorrupt)?;
                let (occurred, recorded) = reader(*seq)?;
                let value = match range.basis {
                    MemoryTimeBasis::Event => occurred,
                    MemoryTimeBasis::Recorded => recorded,
                };
                if range.from_us.is_some_and(|from| value < from)
                    || range.until_us.is_some_and(|until| value >= until)
                {
                    continue;
                }
                if range.basis == MemoryTimeBasis::Event {
                    value
                } else {
                    0
                }
            } else {
                0
            };
            result.loop_count += episode.open_loops.len() as u64;
            selected.insert(
                (-i128::from(clock), -i128::from(*seq), episode.revision_id),
                (episode, *seq),
            );
            if selected.len() > usize::from(query.limit) {
                selected.pop_last();
            }
        }
        // Only observations tied to current scoped input watermarks, not global diagnostics.
        for (run, _) in self.synthesis.runs().values() {
            if std::time::Instant::now() >= deadline {
                result.complete = false;
                break;
            }
            let (Some(id), Some(revision)) = (run.episode_id, run.episode_revision_id) else {
                continue;
            };
            if scoped_work.get(&id) != Some(&run.to_watermark) {
                continue;
            }
            if result.last_run.as_ref().is_none_or(|old| {
                (old.created_at_us, old.run_id) < (run.created_at_us, run.derivation_run_id)
            }) {
                result.last_run = Some(MemoryOverviewRun {
                    run_id: run.derivation_run_id,
                    episode_id: id,
                    input_revision_id: revision,
                    status: run.status,
                    effective_config_hash: run.effective_config_hash,
                    created_at_us: run.created_at_us,
                });
            }
        }
        result.no_inputs &= result.work_count == 0 && result.complete;
        for ((clock, _, _), (episode, seq)) in selected {
            result.episodes.push(inbox_work_row(
                &JournalPayload::WorkEpisodeRecorded(Box::new(episode.clone())),
                seq,
            )?);
            if query
                .time_range
                .as_ref()
                .is_some_and(|range| range.basis == MemoryTimeBasis::Event)
            {
                result.event_times.insert(
                    seq,
                    i64::try_from(-clock).map_err(|_| StoreError::StoreCorrupt)?,
                );
            }
        }
        Ok(result)
    }
}
