//! Scoped overview metadata from canonical work and Inbox indexes.
use super::*;
use evertrace_domain::query::{MemoryOverviewQuery, MemoryTimeBasis};

pub struct MemoryOverviewContext {
    pub frontier: u64,
    pub summaries: memories::MemoryBrowseContext,
    pub facts: memories::MemoryBrowseContext,
    pub methods: memories::MemoryBrowseContext,
    pub reviews: MemoryOverviewReviewContext,
    pub work: MemoryOverviewWorkContext,
}

pub struct MemoryOverviewReviewContext {
    pub page: InboxCurrentContext,
    pub event_times: BTreeMap<u64, i64>,
    pub count: Option<u64>,
    pub scope_available: bool,
    pub complete: bool,
    pub reasons: BTreeMap<String, evertrace_domain::query::InboxReviewReason>,
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

fn work_scopes(
    task_id: TaskId,
    repository: Option<RepositoryId>,
    trees: &[WorktreeId],
) -> Vec<evertrace_domain::semantic::AtomScope> {
    use evertrace_domain::semantic::AtomScope as A;
    let mut scopes = vec![A::Task { task_id }];
    if let Some(repository_instance_id) = repository {
        scopes.push(A::Repository {
            repository_instance_id,
        });
        scopes.extend(trees.iter().map(|id| A::Worktree {
            repository_instance_id,
            worktree_instance_id: *id,
        }));
    }
    scopes
}

impl JournalAdmissionState {
    pub(crate) fn memory_overview_review_context(
        &self,
        query: &MemoryOverviewQuery,
        proof_limit: usize,
        has_failed_job: bool,
        mut times: Option<&mut crate::sqlite_state::JournalTimeReader<'_>>,
    ) -> Result<MemoryOverviewReviewContext, StoreError> {
        use evertrace_domain::query::MemoryScopeSelection as S;
        query.validate().map_err(|_| StoreError::InvalidInput)?;
        if proof_limit == 0 {
            return Err(StoreError::InvalidInput);
        }
        let scope = self.memory_scope_context(query.selection)?;
        let deleted = self.inbox_deleted_products();
        let lanes = self.overview_scope_lanes(query, &scope);
        let mut complete = scope.complete;
        let mut count = 0_u64;
        let mut selected = BTreeMap::new();
        if scope.available {
            for (row_id, value, seq) in self.current_inbox_candidates(&deleted)? {
                let included = if query.selection == S::All {
                    true
                } else if let Some(lane) = match value {
                    InboxCandidate::Lane(v) => Some(v.execution_lane_id),
                    InboxCandidate::Receipt(v) => Some(v.execution_lane_id),
                    _ => None,
                } {
                    match query.selection {
                        S::Global => false,
                        S::Unassigned => !lanes.contains(&lane),
                        _ => lanes.contains(&lane),
                    }
                } else {
                    let scopes = self.overview_review_scopes(value);
                    complete &= scopes.is_some();
                    scope.includes(query.selection, query.include_global, scopes.as_deref())
                };
                if !included {
                    continue;
                }
                let event_clock = if let Some(range) = &query.time_range {
                    let (event, recorded) =
                        times.as_deref_mut().ok_or(StoreError::StoreCorrupt)?(seq)?;
                    if !range.contains(event, recorded) {
                        continue;
                    }
                    (range.basis == MemoryTimeBasis::Event).then_some(event)
                } else {
                    None
                };
                count = count.checked_add(1).ok_or(StoreError::StoreCorrupt)?;
                selected.insert(
                    (
                        -i128::from(event_clock.unwrap_or(0)),
                        -i128::from(seq),
                        row_id.clone(),
                    ),
                    (value, seq, row_id, event_clock),
                );
                if selected.len() > usize::from(query.limit) {
                    selected.pop_last();
                }
            }
        }
        let mut event_times = BTreeMap::new();
        let selected = selected
            .into_values()
            .map(|(value, seq, id, clock)| {
                if let Some(clock) = clock {
                    event_times.insert(seq, clock);
                }
                (value, seq, id)
            })
            .collect();
        let page = self.materialize_inbox(selected, &deleted, proof_limit, has_failed_job, None)?;
        let mut reasons = BTreeMap::new();
        for row in &page.items {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            reasons.insert(
                row.row_id.clone(),
                inbox_review_reason(&payload).ok_or(StoreError::StoreCorrupt)?,
            );
        }
        Ok(MemoryOverviewReviewContext {
            page,
            event_times,
            count: scope.available.then_some(count),
            scope_available: scope.available,
            complete,
            reasons,
        })
    }

    fn overview_scope_lanes(
        &self,
        query: &MemoryOverviewQuery,
        scope: &memories::MemoryScopeContext,
    ) -> BTreeSet<ExecutionLaneId> {
        use evertrace_domain::query::MemoryScopeSelection as S;
        if matches!(query.selection, S::All | S::Global) {
            return BTreeSet::new();
        }
        // Only request-local lane IDs needed by this filter, not a second work graph.
        let streams = self.workstreams.values().map(|(v, _)| {
            (
                v.task_id,
                v.repository_instance_id,
                v.worktree_instance_ids.as_slice(),
                v.execution_lane_ids.as_slice(),
            )
        });
        let episodes = self.episodes.values().map(|(v, _)| {
            (
                v.task_id,
                v.repository_instance_id,
                v.worktree_instance_id.as_slice(),
                v.execution_lane_ids.as_slice(),
            )
        });
        let mut lanes = BTreeSet::new();
        for (task, repository, trees, ids) in streams.chain(episodes) {
            let scopes = work_scopes(task, repository, trees);
            if query.selection == S::Unassigned
                || scope.includes(query.selection, false, Some(&scopes))
            {
                lanes.extend(ids.iter().copied());
            }
        }
        lanes
    }

    fn overview_revision_scopes(
        &self,
        revision: RevisionId,
    ) -> Option<Vec<evertrace_domain::semantic::AtomScope>> {
        let value = if let Some((atom, seq)) = self.atom_revisions.get(&revision) {
            MemoriesCandidate::Atom(atom, *seq)
        } else if let Some((value, seq)) = self.procedure.revision_entry(revision) {
            MemoriesCandidate::Procedure(value, seq)
        } else if let Some((value, seq)) = self.scenario_core.membership_revision_entry(revision) {
            MemoriesCandidate::Membership(value, seq)
        } else {
            return None;
        };
        self.memory_record_scope(value)
    }

    fn overview_review_scopes(
        &self,
        value: InboxCandidate<'_>,
    ) -> Option<Vec<evertrace_domain::semantic::AtomScope>> {
        use evertrace_domain::{
            semantic::AtomScope as A,
            work::{ArtifactScope, SecondaryBindingTarget as T},
        };
        let task = |id| A::Task { task_id: id };
        Some(match value {
            InboxCandidate::Proposal(v) => {
                return self.memory_record_scope(MemoriesCandidate::Proposal(v, 0));
            }
            InboxCandidate::Support(v) => {
                return self.overview_revision_scopes(v.successor_ref.parse().ok()?);
            }
            InboxCandidate::Publication(v) => {
                return self.overview_revision_scopes(v.procedure_revision_id);
            }
            InboxCandidate::Negative(v) => {
                let (negative, _) = self.procedure.negative_entry(v.negative_evidence_id)?;
                let mut scopes = self.overview_revision_scopes(negative.procedure_revision_id)?;
                scopes.push(task(negative.task_id));
                scopes
            }
            InboxCandidate::Episode(v) => work_scopes(
                v.task_id,
                v.repository_instance_id,
                v.worktree_instance_id.as_slice(),
            ),
            InboxCandidate::Attempt(v) => work_scopes(
                v.task_id,
                v.repository_instance_id,
                &v.worktree_instance_ids,
            ),
            InboxCandidate::Competing(v) => vec![task(v.task_id)],
            InboxCandidate::Binding(v) => {
                let mut scopes = v
                    .primary_binding
                    .task_id
                    .map(task)
                    .into_iter()
                    .collect::<Vec<_>>();
                for binding in &v.secondary_bindings {
                    scopes.push(match binding.target_ref {
                        T::Task(id) => task(id),
                        T::Workstream(id) => task(self.workstreams.get(&id)?.0.task_id),
                        T::Episode(id) => task(self.episodes.get(&id)?.0.task_id),
                        T::Attempt(id) => task(self.attempts.get(&id)?.0.task_id),
                        T::CompetingGroup(id) => task(self.competing_groups.get(&id)?.0.task_id),
                        T::ExperimentRun(id) => {
                            let stream = self.experiment_runs.get(&id)?.0.workstream_id;
                            task(self.workstreams.get(&stream)?.0.task_id)
                        }
                        T::Artifact(id) => match self.work_artifacts.get(&id)?.0.revision.scope {
                            ArtifactScope::Task { task_id } => task(task_id),
                            ArtifactScope::Global => A::Global,
                            ArtifactScope::Repository {
                                repository_instance_id,
                            } => A::Repository {
                                repository_instance_id,
                            },
                            ArtifactScope::Worktree {
                                repository_instance_id,
                                worktree_instance_id,
                            } => A::Worktree {
                                repository_instance_id,
                                worktree_instance_id,
                            },
                        },
                    });
                }
                scopes
            }
            InboxCandidate::Transition(v) => {
                [v.from_worktree_instance_id, v.to_worktree_instance_id]
                    .into_iter()
                    .map(|id| {
                        self.worktrees.get(&id).map(|(v, _)| A::Worktree {
                            repository_instance_id: v.repository_instance_id,
                            worktree_instance_id: id,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?
            }
            InboxCandidate::Recovery(v) => vec![A::Worktree {
                repository_instance_id: v.repository_instance_id,
                worktree_instance_id: v.worktree_instance_id,
            }],
            InboxCandidate::Lane(_) | InboxCandidate::Receipt(_) => return None,
        })
    }

    pub(crate) fn memory_overview_work_context(
        &self,
        query: &MemoryOverviewQuery,
        mut times: Option<&mut crate::sqlite_state::JournalTimeReader<'_>>,
    ) -> Result<MemoryOverviewWorkContext, StoreError> {
        use evertrace_domain::work::EpisodeLifecycle;
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
            let scopes = work_scopes(
                episode.task_id,
                episode.repository_instance_id,
                episode.worktree_instance_id.as_slice(),
            );
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
