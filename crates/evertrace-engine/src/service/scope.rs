use std::path::Path;

use evertrace_codex::binding::{BindingAnchor, PublicWorkspace, valid_lexical_absolute_path};
use evertrace_domain::{
    ids::{RepositoryId, TaskId, WorkEpisodeId, WorkstreamId, WorktreeId},
    repository::{RepositoryInstance, WorktreeInstance, WorktreeLifecycle},
    work::{EpisodeLifecycle, LaneStatus, Task, TaskLifecycle, WorkEpisode, WorkstreamStatus},
};
use evertrace_store::{JournalPayload, ObjectRowKind, ProjectionSnapshot};

use super::{McpResolvedScope, McpScopeMechanism};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpQueryAnchor {
    pub mechanism: McpScopeMechanism,
    pub task_id: Option<TaskId>,
    pub workstream_id: Option<WorkstreamId>,
    pub episode_id: Option<WorkEpisodeId>,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub cwd_only: bool,
}

pub fn resolve_query_anchor(
    snapshot: &ProjectionSnapshot,
    binding: &McpResolvedScope,
    client_cwd: &str,
) -> Option<McpQueryAnchor> {
    if !valid_lexical_absolute_path(client_cwd) {
        return None;
    }
    match (&binding.anchor, binding.mechanism, &binding.workspace) {
        (Some(anchor), McpScopeMechanism::ExactClaim | McpScopeMechanism::ConnectionScoped, _) => {
            let active = exact_anchor(snapshot, anchor, binding.mechanism)?;
            select_workspace(snapshot, active, &binding.workspace)
        }
        (None, McpScopeMechanism::CwdOnly, PublicWorkspace::Active) => {
            cwd_anchor(snapshot, client_cwd)
        }
        (None, McpScopeMechanism::Explicit, PublicWorkspace::Repository(id)) => {
            unique_repository(snapshot, *id).map(|_| McpQueryAnchor {
                mechanism: McpScopeMechanism::Explicit,
                task_id: None,
                workstream_id: None,
                episode_id: None,
                repository_id: Some(*id),
                worktree_id: None,
                cwd_only: false,
            })
        }
        (None, McpScopeMechanism::Explicit, PublicWorkspace::Worktree(id)) => {
            let worktree = unique_worktree(snapshot, *id)?;
            Some(McpQueryAnchor {
                mechanism: McpScopeMechanism::Explicit,
                task_id: None,
                workstream_id: None,
                episode_id: None,
                repository_id: Some(worktree.repository_instance_id),
                worktree_id: Some(*id),
                cwd_only: false,
            })
        }
        (None, McpScopeMechanism::Explicit, PublicWorkspace::PathHint(path)) => {
            cwd_anchor(snapshot, path)
        }
        _ => None,
    }
}

fn select_workspace(
    snapshot: &ProjectionSnapshot,
    mut active: McpQueryAnchor,
    workspace: &PublicWorkspace,
) -> Option<McpQueryAnchor> {
    match workspace {
        PublicWorkspace::Active => Some(active),
        PublicWorkspace::Repository(id) => {
            unique_repository(snapshot, *id)?;
            active.repository_id = Some(*id);
            active.worktree_id = None;
            Some(active)
        }
        PublicWorkspace::Worktree(id) => {
            let worktree = unique_worktree(snapshot, *id)?;
            unique_repository(snapshot, worktree.repository_instance_id)?;
            active.repository_id = Some(worktree.repository_instance_id);
            active.worktree_id = Some(*id);
            Some(active)
        }
        PublicWorkspace::PathHint(path) => {
            let resolved = cwd_anchor(snapshot, path)?;
            active.repository_id = resolved.repository_id;
            active.worktree_id = resolved.worktree_id;
            Some(active)
        }
    }
}

fn exact_anchor(
    snapshot: &ProjectionSnapshot,
    anchor: &BindingAnchor,
    mechanism: McpScopeMechanism,
) -> Option<McpQueryAnchor> {
    let lanes = payloads(snapshot, "execution_lane").filter_map(|payload| match payload {
        JournalPayload::ExecutionLaneRecorded(value)
            if value.host_session_id == anchor.session_id
                && anchor
                    .agent_id
                    .as_deref()
                    .is_none_or(|agent| value.agent_id == agent)
                && value.status == LaneStatus::Active =>
        {
            Some(*value)
        }
        _ => None,
    });
    let lane = exactly_one(lanes)?;
    let workstreams = payloads(snapshot, "workstream").filter_map(|payload| match payload {
        JournalPayload::WorkstreamRecorded(value)
            if value.status == WorkstreamStatus::Active
                && value.execution_lane_ids.contains(&lane.execution_lane_id) =>
        {
            Some(*value)
        }
        _ => None,
    });
    let workstream = exactly_one(workstreams)?;
    let task = payloads(snapshot, "task").filter_map(|payload| match payload {
        JournalPayload::TaskRecorded(value)
            if value.task_id == workstream.task_id && value.lifecycle == TaskLifecycle::Active =>
        {
            Some(*value)
        }
        _ => None,
    });
    let _task: Task = exactly_one(task)?;
    let episode_id = workstream.active_episode_id?;
    let episodes = payloads(snapshot, "work_episode").filter_map(|payload| match payload {
        JournalPayload::WorkEpisodeRecorded(value)
            if value.episode_id == episode_id
                && value.lifecycle_status == EpisodeLifecycle::Open
                && value.task_id == workstream.task_id
                && value.workstream_id == workstream.workstream_id
                && value.execution_lane_ids.contains(&lane.execution_lane_id)
                && value.session_ids.contains(&anchor.session_id) =>
        {
            Some(*value)
        }
        _ => None,
    });
    let episode: WorkEpisode = exactly_one(episodes)?;
    if episode.repository_instance_id != workstream.repository_instance_id
        || episode.worktree_instance_id != workstream.active_worktree_instance_id
    {
        return None;
    }
    if let Some(repository_id) = workstream.repository_instance_id {
        unique_repository(snapshot, repository_id)?;
    }
    if let Some(worktree_id) = workstream.active_worktree_instance_id {
        let worktree = unique_worktree(snapshot, worktree_id)?;
        if Some(worktree.repository_instance_id) != workstream.repository_instance_id {
            return None;
        }
    }
    Some(McpQueryAnchor {
        mechanism,
        task_id: Some(workstream.task_id),
        workstream_id: Some(workstream.workstream_id),
        episode_id: Some(episode.episode_id),
        repository_id: workstream.repository_instance_id,
        worktree_id: workstream.active_worktree_instance_id,
        cwd_only: false,
    })
}

fn cwd_anchor(snapshot: &ProjectionSnapshot, cwd: &str) -> Option<McpQueryAnchor> {
    let cwd = Path::new(cwd);
    let mut worktrees = payloads(snapshot, "worktree").filter_map(|payload| match payload {
        JournalPayload::WorktreeInstanceRecorded(value)
            if value.lifecycle == WorktreeLifecycle::Active
                && value
                    .current_path
                    .as_deref()
                    .is_some_and(|path| cwd.starts_with(path)) =>
        {
            Some(*value)
        }
        _ => None,
    });
    let worktree = worktrees.next();
    if worktrees.next().is_some() {
        return None;
    }
    if let Some(worktree) = worktree {
        unique_repository(snapshot, worktree.repository_instance_id)?;
        return Some(McpQueryAnchor {
            mechanism: McpScopeMechanism::CwdOnly,
            task_id: None,
            workstream_id: None,
            episode_id: None,
            repository_id: Some(worktree.repository_instance_id),
            worktree_id: Some(worktree.worktree_instance_id),
            cwd_only: true,
        });
    }
    let repositories = payloads(snapshot, "repository").filter_map(|payload| match payload {
        JournalPayload::RepositoryInstanceRecorded(value)
            if cwd.starts_with(&value.current_path) =>
        {
            Some(*value)
        }
        _ => None,
    });
    let repository = exactly_one(repositories)?;
    Some(McpQueryAnchor {
        mechanism: McpScopeMechanism::CwdOnly,
        task_id: None,
        workstream_id: None,
        episode_id: None,
        repository_id: Some(repository.repository_id),
        worktree_id: None,
        cwd_only: true,
    })
}

fn unique_repository(
    snapshot: &ProjectionSnapshot,
    id: RepositoryId,
) -> Option<RepositoryInstance> {
    exactly_one(
        payloads(snapshot, "repository").filter_map(|payload| match payload {
            JournalPayload::RepositoryInstanceRecorded(value) if value.repository_id == id => {
                Some(*value)
            }
            _ => None,
        }),
    )
}

fn unique_worktree(snapshot: &ProjectionSnapshot, id: WorktreeId) -> Option<WorktreeInstance> {
    exactly_one(
        payloads(snapshot, "worktree").filter_map(|payload| match payload {
            JournalPayload::WorktreeInstanceRecorded(value)
                if value.worktree_instance_id == id
                    && value.lifecycle == WorktreeLifecycle::Active =>
            {
                Some(*value)
            }
            _ => None,
        }),
    )
}

fn payloads<'a>(
    snapshot: &'a ProjectionSnapshot,
    object_kind: &'a str,
) -> impl Iterator<Item = JournalPayload> + 'a {
    snapshot.rows.iter().filter_map(|row| {
        (row.row_kind == ObjectRowKind::Data
            && row.row_class == Some(evertrace_store::ObjectRowClass::Object)
            && row.object_kind.as_deref() == Some(object_kind))
        .then_some(row.payload_json.as_deref()?)
        .and_then(|payload| serde_json::from_str(payload).ok())
    })
}

fn exactly_one<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation, WorktreeKind,
    };
    use evertrace_domain::{
        ids::{CaptureReceiptId, ExecutionLaneId},
        revision::RevisionId,
        work::{
            CoverageLevel, ExecutionLane, LivenessState, OrderingIntegrity, PairingIntegrity,
            PayloadIntegrity, PhaseContract, PhaseKind, ReasoningVisibility, SourceCoverage,
            TaskIdentityConfidence, TaskScopeMembership, Workstream,
        },
    };
    use evertrace_store::{ObjectFamily, ObjectRow, ObjectRowClass};

    fn repository(id: RepositoryId, path: &str) -> RepositoryInstance {
        RepositoryInstance {
            repository_id: id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: path.into(),
            path_history: vec![PathObservation {
                path: path.into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["evidence".into()],
            }],
            git_common_dir_path: Some(format!("{path}/.git")),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 1,
                inode: 1,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: Vec::new(),
            derived_from: None,
            identity_evidence_refs: vec!["evidence".into()],
            recorded_at_us: 1,
        }
    }

    fn worktree(id: WorktreeId, repository: RepositoryId, path: &str) -> WorktreeInstance {
        let observation = PathObservation {
            path: path.into(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["evidence".into()],
        };
        WorktreeInstance {
            worktree_instance_id: id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(path.into()),
            path_history: vec![observation.clone()],
            git_admin_path_history: vec![observation],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: None,
            created_event_ref: "created".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        }
    }

    fn row(id: &str, kind: &str, payload: JournalPayload) -> ObjectRow {
        ObjectRow {
            row_id: id.into(),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: Some(ObjectFamily::Work),
            object_kind: Some(kind.into()),
            object_id: Some(id.into()),
            current_revision_id: None,
            lifecycle: Some("active".into()),
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some(serde_json::to_string(&payload).unwrap()),
            source_event_seq: 1,
            projection_generation: 1,
        }
    }

    fn binding(workspace: PublicWorkspace, mechanism: McpScopeMechanism) -> McpResolvedScope {
        McpResolvedScope {
            workspace,
            anchor: None,
            mechanism,
        }
    }

    fn exact_fixture() -> (
        ProjectionSnapshot,
        BindingAnchor,
        TaskId,
        WorkstreamId,
        WorkEpisodeId,
    ) {
        let task_id = TaskId::new_v7();
        let workstream_id = WorkstreamId::new_v7();
        let lane_id = ExecutionLaneId::new_v7();
        let phase = PhaseContract {
            local_goal: "scope test".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "implement".into(),
            primary_targets: vec!["scope".into()],
            entry_conditions: vec!["bound".into()],
            acceptance_boundary: "exact".into(),
            expected_state_transition: "resolved".into(),
        };
        let task = Task {
            task_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: vec!["request".into()],
            canonical_goal: "scope test".into(),
            scope_memberships: vec![TaskScopeMembership {
                repository_instance_id: None,
                worktree_instance_ids: Vec::new(),
            }],
            identity_confidence: TaskIdentityConfidence::Explicit,
            lifecycle: TaskLifecycle::Active,
            continuation_of_task_id: None,
            split_from_task_id: None,
            split_into_task_ids: Vec::new(),
            merged_from_task_ids: Vec::new(),
            merged_into_task_id: None,
            created_at_us: 1,
            closed_at_us: None,
            source_watermark: 1,
        };
        let mut workstream = Workstream {
            workstream_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            task_id,
            repository_instance_id: None,
            worktree_instance_ids: Vec::new(),
            active_worktree_instance_id: None,
            worktree_lineage_refs: Vec::new(),
            parent_workstream_id: None,
            dependency_workstream_ids: Vec::new(),
            status: WorkstreamStatus::Active,
            root_goal: "scope test".into(),
            workstream_goal: "resolve".into(),
            target_family: "scope".into(),
            hypothesis_or_failure_family: "binding".into(),
            acceptance_boundary: "exact".into(),
            phase_contract: phase,
            active_episode_id: None,
            execution_lane_ids: vec![lane_id],
            source_watermark: 1,
        };
        let mut episode = crate::work::new_episode(&workstream, None, 1).unwrap();
        episode.session_ids = vec!["session-exact".into()];
        episode.execution_lane_ids = vec![lane_id];
        workstream.active_episode_id = Some(episode.episode_id);
        workstream.predecessor_revision_id = Some(RevisionId::new_v7());
        let lane = ExecutionLane {
            execution_lane_id: lane_id,
            lane_revision: 1,
            predecessor_revision: None,
            host_session_id: "session-exact".into(),
            agent_id: "agent".into(),
            host_lane_key: "lane".into(),
            incarnation_ref: "incarnation".into(),
            parent_lane_id: None,
            parent_host_lane_key: None,
            spawn_event_ref: None,
            terminal_event_ref: None,
            termination_evidence_refs: Vec::new(),
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            status: LaneStatus::Active,
            terminal_kind: None,
            liveness_state: LivenessState::Live,
            liveness_probe_refs: vec!["probe".into()],
            finalized: false,
            event_watermark: 1,
            adapter_manifest_ids: vec!["adapter".into()],
            active_capture_receipt_revision_id: CaptureReceiptId::new_v7(),
            coverage_level: CoverageLevel::Full,
            source_coverage: SourceCoverage::Open,
            pairing_integrity: PairingIntegrity::Complete,
            payload_integrity: PayloadIntegrity::Complete,
            ordering_integrity: OrderingIntegrity::Complete,
            reasoning_visibility: vec![ReasoningVisibility::ExplicitRationale],
            operation_ids: Vec::new(),
            correction_reason: None,
        };
        let episode_id = episode.episode_id;
        (
            ProjectionSnapshot {
                frontier: 4,
                rows: vec![
                    row(
                        "lane",
                        "execution_lane",
                        JournalPayload::ExecutionLaneRecorded(Box::new(lane)),
                    ),
                    row("task", "task", JournalPayload::TaskRecorded(Box::new(task))),
                    row(
                        "workstream",
                        "workstream",
                        JournalPayload::WorkstreamRecorded(Box::new(workstream)),
                    ),
                    row(
                        "episode",
                        "work_episode",
                        JournalPayload::WorkEpisodeRecorded(Box::new(episode)),
                    ),
                ],
            },
            BindingAnchor {
                session_id: "session-exact".into(),
                turn_id: "turn".into(),
                tool_use_id: "tool".into(),
                agent_id: None,
            },
            task_id,
            workstream_id,
            episode_id,
        )
    }

    #[test]
    fn cwd_and_explicit_identity_require_unique_current_projection_rows() {
        let repository_id = RepositoryId::new_v7();
        let worktree_id = WorktreeId::new_v7();
        let repository = repository(repository_id, "/workspace/repo");
        let worktree = worktree(worktree_id, repository_id, "/workspace/repo/wt");
        let mut snapshot = ProjectionSnapshot {
            frontier: 2,
            rows: vec![
                row(
                    "repository",
                    "repository",
                    JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
                ),
                row(
                    "worktree",
                    "worktree",
                    JournalPayload::WorktreeInstanceRecorded(Box::new(worktree.clone())),
                ),
            ],
        };
        let cwd = resolve_query_anchor(
            &snapshot,
            &binding(PublicWorkspace::Active, McpScopeMechanism::CwdOnly),
            "/workspace/repo/wt/src",
        )
        .unwrap();
        assert!(cwd.cwd_only);
        assert_eq!(cwd.repository_id, Some(repository_id));
        assert_eq!(cwd.worktree_id, Some(worktree_id));
        assert!(cwd.task_id.is_none());
        assert!(
            resolve_query_anchor(
                &snapshot,
                &binding(
                    PublicWorkspace::Repository(repository_id),
                    McpScopeMechanism::Explicit
                ),
                "/elsewhere",
            )
            .is_some()
        );
        assert!(
            resolve_query_anchor(
                &snapshot,
                &binding(
                    PublicWorkspace::Worktree(WorktreeId::new_v7()),
                    McpScopeMechanism::Explicit
                ),
                "/elsewhere",
            )
            .is_none()
        );

        snapshot.rows.push(row(
            "worktree-duplicate",
            "worktree",
            JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
        ));
        assert!(
            resolve_query_anchor(
                &snapshot,
                &binding(PublicWorkspace::Active, McpScopeMechanism::CwdOnly),
                "/workspace/repo/wt/src",
            )
            .is_none()
        );
        snapshot.rows.push(row(
            "repository-duplicate",
            "repository",
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
        ));
        assert!(
            resolve_query_anchor(
                &snapshot,
                &binding(
                    PublicWorkspace::Repository(repository_id),
                    McpScopeMechanism::Explicit
                ),
                "/elsewhere",
            )
            .is_none()
        );
    }

    #[test]
    fn exact_chain_is_unique_and_explicit_workspace_overrides_only_the_shard() {
        let (mut snapshot, anchor, task_id, workstream_id, episode_id) = exact_fixture();
        let repository_id = RepositoryId::new_v7();
        snapshot.rows.push(row(
            "explicit-repository",
            "repository",
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository(
                repository_id,
                "/explicit/repo",
            ))),
        ));
        let exact = McpResolvedScope {
            workspace: PublicWorkspace::Active,
            anchor: Some(anchor.clone()),
            mechanism: McpScopeMechanism::ExactClaim,
        };
        let resolved = resolve_query_anchor(&snapshot, &exact, "/cwd").unwrap();
        assert_eq!(resolved.task_id, Some(task_id));
        assert_eq!(resolved.workstream_id, Some(workstream_id));
        assert_eq!(resolved.episode_id, Some(episode_id));
        assert!(resolved.repository_id.is_none());

        let overridden = resolve_query_anchor(
            &snapshot,
            &McpResolvedScope {
                workspace: PublicWorkspace::Repository(repository_id),
                anchor: Some(anchor),
                mechanism: McpScopeMechanism::ExactClaim,
            },
            "/cwd",
        )
        .unwrap();
        assert_eq!(overridden.task_id, Some(task_id));
        assert_eq!(overridden.workstream_id, Some(workstream_id));
        assert_eq!(overridden.episode_id, Some(episode_id));
        assert_eq!(overridden.repository_id, Some(repository_id));
    }

    #[test]
    fn every_exact_chain_stage_rejects_zero_and_multiple_current_candidates() {
        for kind in ["execution_lane", "workstream", "work_episode", "task"] {
            let (snapshot, anchor, _, _, _) = exact_fixture();
            let binding = McpResolvedScope {
                workspace: PublicWorkspace::Active,
                anchor: Some(anchor),
                mechanism: McpScopeMechanism::ExactClaim,
            };
            let mut missing = snapshot.clone();
            missing
                .rows
                .retain(|row| row.object_kind.as_deref() != Some(kind));
            assert!(resolve_query_anchor(&missing, &binding, "/cwd").is_none());

            let mut multiple = snapshot;
            let mut duplicate = multiple
                .rows
                .iter()
                .find(|row| row.object_kind.as_deref() == Some(kind))
                .unwrap()
                .clone();
            duplicate.row_id = format!("duplicate-{kind}");
            multiple.rows.push(duplicate);
            assert!(resolve_query_anchor(&multiple, &binding, "/cwd").is_none());
        }
    }

    #[test]
    fn exact_agent_id_disambiguates_active_lanes_without_nearest_fallback() {
        let (mut snapshot, mut anchor, task_id, _, _) = exact_fixture();
        let lane_payload = snapshot
            .rows
            .iter()
            .find(|row| row.object_kind.as_deref() == Some("execution_lane"))
            .and_then(|row| row.payload_json.as_deref())
            .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            .unwrap();
        let JournalPayload::ExecutionLaneRecorded(mut other_lane) = lane_payload else {
            unreachable!()
        };
        other_lane.execution_lane_id = ExecutionLaneId::new_v7();
        other_lane.agent_id = "other-agent".into();
        snapshot.rows.push(row(
            "other-lane",
            "execution_lane",
            JournalPayload::ExecutionLaneRecorded(other_lane),
        ));
        let binding = |anchor: BindingAnchor| McpResolvedScope {
            workspace: PublicWorkspace::Active,
            anchor: Some(anchor),
            mechanism: McpScopeMechanism::ExactClaim,
        };
        assert!(resolve_query_anchor(&snapshot, &binding(anchor.clone()), "/cwd").is_none());
        anchor.agent_id = Some("agent".into());
        assert_eq!(
            resolve_query_anchor(&snapshot, &binding(anchor.clone()), "/cwd")
                .and_then(|value| value.task_id),
            Some(task_id)
        );
        anchor.agent_id = Some("missing-agent".into());
        assert!(resolve_query_anchor(&snapshot, &binding(anchor), "/cwd").is_none());
    }
}
