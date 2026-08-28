use std::time::SystemTime;

use evertrace_domain::{
    ids::{CommandId, RepositoryId, TaskId, WorkstreamId, WorktreeId},
    repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
        RepositoryInstance, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    work::{
        CorrelationEvidence, CorrelationEvidenceKind, CorrelationResult, PhaseContract, PhaseKind,
        Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership, Workstream,
        WorkstreamStatus,
    },
};
use evertrace_engine::work::{
    TypedTaskChange, TypedWorkstreamChange, WorkCommandContext,
    task::{continue_task, create_task, merge_tasks, revise_task, split_task},
    workstream::{
        CorrelationScope, create_workstream, derive_active_lineage,
        replace_workstream_for_material_goal, resolve_workstream_candidate, revise_workstream,
        validate_workstream_scope,
    },
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, JournalWriter, StoreError,
    WorkIdentityCurrentView, reduce_journal,
    relations::{WorkIdentityRelationKind, build_work_identity_relation_rows},
    repository::RepositoryCurrentView,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [0x12; 32];
const ALGO: &str = "s12-work-v1";

fn context(at: i64) -> WorkCommandContext {
    WorkCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: ALGO,
    }
}

fn task(goal: &str, watermark: u64) -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec![format!("request-{watermark}")],
        canonical_goal: goal.into(),
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
        created_at_us: i64::try_from(watermark).unwrap(),
        closed_at_us: None,
        source_watermark: watermark,
    }
}

fn successor(current: &Task, lifecycle: TaskLifecycle, watermark: u64) -> Task {
    let mut next = current.clone();
    next.revision_id = RevisionId::new_v7();
    next.predecessor_revision_id = Some(current.revision_id);
    next.lifecycle = lifecycle;
    next.source_watermark = watermark;
    next.closed_at_us = lifecycle
        .is_terminal()
        .then_some(i64::try_from(watermark).unwrap());
    next
}

fn phase() -> PhaseContract {
    PhaseContract {
        local_goal: "implement work identity".into(),
        phase_kind: PhaseKind::Implement,
        phase_label: "s12".into(),
        primary_targets: vec!["task".into(), "workstream".into()],
        entry_conditions: vec!["s11_complete".into()],
        acceptance_boundary: "tests_pass".into(),
        expected_state_transition: "s12_complete".into(),
    }
}

fn workstream(task_id: TaskId, goal: &str, watermark: u64) -> Workstream {
    Workstream {
        workstream_id: WorkstreamId::new_v7(),
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
        root_goal: goal.into(),
        workstream_goal: goal.into(),
        target_family: "non_code".into(),
        hypothesis_or_failure_family: "identity".into(),
        acceptance_boundary: "accepted".into(),
        phase_contract: phase(),
        active_episode_id: None,
        execution_lane_ids: Vec::new(),
        source_watermark: watermark,
    }
}

fn repository(id: RepositoryId, ordinal: u64) -> RepositoryInstance {
    let path = format!("/tmp/s12-repository-{ordinal}");
    RepositoryInstance {
        repository_id: id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![PathObservation {
            path: path.clone(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec![format!("repo-evidence-{ordinal}")],
        }],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 1,
            inode: ordinal,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec![format!("repo-identity-{ordinal}")],
        recorded_at_us: 1,
    }
}

fn worktree(id: WorktreeId, repository_id: RepositoryId, ordinal: u64) -> WorktreeInstance {
    let path = format!("/tmp/s12-worktree-{ordinal}");
    WorktreeInstance {
        worktree_instance_id: id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind: WorktreeKind::Main,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.clone()),
        path_history: vec![PathObservation {
            path: path.clone(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec![format!("worktree-evidence-{ordinal}")],
        }],
        git_admin_path_history: vec![PathObservation {
            path: format!("{path}/.git"),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec![format!("worktree-admin-{ordinal}")],
        }],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: None,
        created_event_ref: format!("worktree-created-{ordinal}"),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    }
}

#[tokio::test]
async fn task_is_cross_session_and_session_events_create_no_delta() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let root = task("cross session goal", 1);
    writer
        .commit(&create_task(context(1), root.clone()).unwrap(), 1)
        .await
        .unwrap();
    let first = writer.project().await.unwrap();
    let view = WorkIdentityCurrentView::from_snapshot(&first).unwrap();
    assert_eq!(view.tasks.get(&root.task_id), Some(&root));
    let second = writer.project().await.unwrap();
    assert_eq!(first, second);
    assert_eq!(writer.journal_rows().await.unwrap().len(), 3);
}

#[tokio::test]
async fn one_session_can_hold_multiple_tasks_and_non_code_scope() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let first = task("first", 1);
    let second = task("second", 2);
    writer
        .commit(&create_task(context(1), first.clone()).unwrap(), 1)
        .await
        .unwrap();
    writer
        .commit(&create_task(context(2), second.clone()).unwrap(), 2)
        .await
        .unwrap();
    let view = WorkIdentityCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert_eq!(view.tasks.len(), 2);
    assert!(view.tasks.values().all(|task| {
        task.scope_memberships
            .iter()
            .all(|membership| membership.repository_instance_id.is_none())
    }));
}

#[tokio::test]
async fn task_successors_are_immutable_and_terminal_tasks_do_not_revive() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let root = task("goal", 1);
    writer
        .commit(&create_task(context(1), root.clone()).unwrap(), 1)
        .await
        .unwrap();
    let mut changed = successor(&root, TaskLifecycle::Completed, 2);
    changed.canonical_goal = "goal accepted".into();
    writer
        .commit(
            &revise_task(
                context(2),
                &root,
                changed.clone(),
                TypedTaskChange::Lifecycle,
                &["completion-evidence".into()],
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();
    let revival = successor(&changed, TaskLifecycle::Active, 3);
    let forged = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            3,
            CONFIG,
            ALGO,
            JournalPayload::TaskRecorded(Box::new(revival)),
        )],
    )
    .unwrap();
    assert_eq!(
        writer.commit(&forged, 3).await.unwrap_err(),
        StoreError::InvalidInput
    );
}

#[tokio::test]
async fn completed_task_continuation_uses_new_identity_without_inheritance() {
    let source = {
        let root = task("old", 1);
        successor(&root, TaskLifecycle::Completed, 2)
    };
    let mut continuation = task("continued", 3);
    continuation.continuation_of_task_id = Some(source.task_id);
    continuation.scope_memberships.clear();
    let command = continue_task(
        context(3),
        &source,
        continuation.clone(),
        &["explicit-continuation".into()],
    )
    .unwrap();
    assert_ne!(continuation.task_id, source.task_id);
    assert!(continuation.scope_memberships.is_empty());
    assert_eq!(command.events().len(), 1);

    let abandoned_source = successor(&task("abandoned", 4), TaskLifecycle::Abandoned, 5);
    let mut abandoned_continuation = task("abandoned continuation", 6);
    abandoned_continuation.continuation_of_task_id = Some(abandoned_source.task_id);
    abandoned_continuation.scope_memberships.clear();
    assert!(
        continue_task(
            context(6),
            &abandoned_source,
            abandoned_continuation,
            &["explicit-continuation".into()],
        )
        .is_ok()
    );

    for lifecycle in [
        TaskLifecycle::Active,
        TaskLifecycle::Paused,
        TaskLifecycle::Superseded,
    ] {
        let mut disallowed = task("same identity must continue", 7);
        disallowed.lifecycle = lifecycle;
        disallowed.closed_at_us = lifecycle.is_terminal().then_some(8);
        let mut fork = task("illegal continuation", 9);
        fork.continuation_of_task_id = Some(disallowed.task_id);
        fork.scope_memberships.clear();
        assert!(
            continue_task(
                context(9),
                &disallowed,
                fork,
                &["explicit-but-invalid-lifecycle".into()],
            )
            .is_err()
        );
    }
}

#[test]
fn split_and_merge_are_atomic_and_do_not_inherit_scope() {
    let source = task("source", 1);
    let mut child_a = task("child a", 3);
    let mut child_b = task("child b", 3);
    child_a.split_from_task_id = Some(source.task_id);
    child_b.split_from_task_id = Some(source.task_id);
    child_a.scope_memberships.clear();
    child_b.scope_memberships.clear();
    let mut source_split = successor(&source, TaskLifecycle::Superseded, 2);
    source_split.split_into_task_ids = vec![child_a.task_id, child_b.task_id];
    source_split.split_into_task_ids.sort();
    let split = split_task(
        context(2),
        source_split,
        vec![child_a.clone(), child_b.clone()],
        &["split-decision".into()],
    )
    .unwrap();
    assert_eq!(split.events().len(), 3);

    let mut merged = task("merged", 5);
    merged.scope_memberships.clear();
    merged.merged_from_task_ids = vec![child_a.task_id, child_b.task_id];
    merged.merged_from_task_ids.sort();
    let mut a_done = successor(&child_a, TaskLifecycle::Superseded, 4);
    let mut b_done = successor(&child_b, TaskLifecycle::Superseded, 4);
    a_done.merged_into_task_id = Some(merged.task_id);
    b_done.merged_into_task_id = Some(merged.task_id);
    let command = merge_tasks(
        context(5),
        vec![a_done, b_done],
        merged,
        &["merge-decision".into()],
    )
    .unwrap();
    assert_eq!(command.events().len(), 3);
    assert!(matches!(
        command.events()[0].payload,
        JournalPayload::TaskRecorded(_)
    ));
}

#[tokio::test]
async fn partial_split_and_merge_commands_fail_before_frontier_changes() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let source = task("split source", 1);
    writer
        .commit(&create_task(context(1), source.clone()).unwrap(), 1)
        .await
        .unwrap();
    let child_a = task("child a", 3);
    let child_b = task("child b", 3);
    let mut partial_source = successor(&source, TaskLifecycle::Superseded, 2);
    partial_source.split_into_task_ids = vec![child_a.task_id, child_b.task_id];
    partial_source.split_into_task_ids.sort();
    let partial_split = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            2,
            CONFIG,
            ALGO,
            JournalPayload::TaskRecorded(Box::new(partial_source)),
        )],
    )
    .unwrap();
    let before_rows = writer.journal_rows().await.unwrap();
    let before_projection = writer.project().await.unwrap();
    assert_eq!(
        writer.commit(&partial_split, 2).await.unwrap_err(),
        StoreError::InvalidInput
    );
    assert_eq!(writer.journal_rows().await.unwrap(), before_rows);
    assert_eq!(writer.project().await.unwrap(), before_projection);

    let source_b = task("merge source b", 4);
    writer
        .commit(&create_task(context(4), source_b.clone()).unwrap(), 4)
        .await
        .unwrap();
    let mut merged = task("merged", 5);
    merged.scope_memberships.clear();
    merged.merged_from_task_ids = vec![source.task_id, source_b.task_id];
    merged.merged_from_task_ids.sort();
    let partial_merge = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            5,
            CONFIG,
            ALGO,
            JournalPayload::TaskRecorded(Box::new(merged)),
        )],
    )
    .unwrap();
    let before_rows = writer.journal_rows().await.unwrap();
    let before_projection = writer.project().await.unwrap();
    assert_eq!(
        writer.commit(&partial_merge, 5).await.unwrap_err(),
        StoreError::InvalidInput
    );
    assert_eq!(writer.journal_rows().await.unwrap(), before_rows);
    assert_eq!(writer.project().await.unwrap(), before_projection);
}

#[tokio::test]
async fn workstream_dependency_dag_and_cross_task_edges_fail_closed() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let task_a = task("a", 1);
    let task_b = task("b", 2);
    let repository_view = RepositoryCurrentView::default();
    writer
        .commit(&create_task(context(1), task_a.clone()).unwrap(), 1)
        .await
        .unwrap();
    writer
        .commit(&create_task(context(2), task_b.clone()).unwrap(), 2)
        .await
        .unwrap();
    let first = workstream(task_a.task_id, "first", 3);
    writer
        .commit(
            &create_workstream(context(3), &task_a, &repository_view, first.clone()).unwrap(),
            3,
        )
        .await
        .unwrap();
    let mut second = workstream(task_a.task_id, "second", 4);
    second.dependency_workstream_ids = vec![first.workstream_id];
    writer
        .commit(
            &create_workstream(context(4), &task_a, &repository_view, second.clone()).unwrap(),
            4,
        )
        .await
        .unwrap();
    let mut cycle = first.clone();
    cycle.revision_id = RevisionId::new_v7();
    cycle.predecessor_revision_id = Some(first.revision_id);
    cycle.dependency_workstream_ids = vec![second.workstream_id];
    cycle.source_watermark = 5;
    let cycle_command = revise_workstream(
        context(5),
        &task_a,
        &repository_view,
        &first,
        cycle,
        TypedWorkstreamChange::StructuredRevision,
        &["dependency-change".into()],
    )
    .unwrap();
    assert_eq!(
        writer.commit(&cycle_command, 5).await.unwrap_err(),
        StoreError::InvalidInput
    );
    let mut cross = workstream(task_b.task_id, "cross", 6);
    cross.dependency_workstream_ids = vec![first.workstream_id];
    let error = writer
        .commit(
            &create_workstream(context(6), &task_b, &repository_view, cross).unwrap(),
            6,
        )
        .await
        .unwrap_err();
    assert_eq!(error, StoreError::InvalidInput);
}

#[test]
fn cross_repository_task_uses_two_single_repository_shards() {
    let repo_a = RepositoryId::new_v7();
    let repo_b = RepositoryId::new_v7();
    let worktree_a = WorktreeId::new_v7();
    let worktree_b = WorktreeId::new_v7();
    let repository_view = RepositoryCurrentView {
        repositories: [
            (repo_a, repository(repo_a, 1)),
            (repo_b, repository(repo_b, 2)),
        ]
        .into(),
        worktrees: [
            (worktree_a, worktree(worktree_a, repo_a, 1)),
            (worktree_b, worktree(worktree_b, repo_b, 2)),
        ]
        .into(),
        ..RepositoryCurrentView::default()
    };
    let mut task = task("cross repository", 1);
    task.scope_memberships = vec![
        TaskScopeMembership {
            repository_instance_id: Some(repo_a),
            worktree_instance_ids: vec![worktree_a],
        },
        TaskScopeMembership {
            repository_instance_id: Some(repo_b),
            worktree_instance_ids: vec![worktree_b],
        },
    ];
    task.scope_memberships.sort();
    let mut shard_a = workstream(task.task_id, "repo a", 2);
    shard_a.repository_instance_id = Some(repo_a);
    shard_a.worktree_instance_ids = vec![worktree_a];
    shard_a.active_worktree_instance_id = Some(worktree_a);
    let mut shard_b = workstream(task.task_id, "repo b", 3);
    shard_b.repository_instance_id = Some(repo_b);
    shard_b.worktree_instance_ids = vec![worktree_b];
    shard_b.active_worktree_instance_id = Some(worktree_b);
    shard_b.dependency_workstream_ids = vec![shard_a.workstream_id];
    assert!(validate_workstream_scope(&task, &shard_a, &repository_view).is_ok());
    assert!(validate_workstream_scope(&task, &shard_b, &repository_view).is_ok());
    assert!(derive_active_lineage(&task, &shard_a, &repository_view).is_ok());
    assert!(derive_active_lineage(&task, &shard_b, &repository_view).is_ok());
    let mut mixed = shard_a.clone();
    mixed.worktree_instance_ids.push(worktree_b);
    mixed.worktree_instance_ids.sort();
    assert!(validate_workstream_scope(&task, &mixed, &repository_view).is_err());
}

#[tokio::test]
async fn workstream_scope_must_be_a_subset_of_task_membership_at_every_boundary() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let repository_id = RepositoryId::new_v7();
    let member_worktree_id = WorktreeId::new_v7();
    let outside_worktree_id = WorktreeId::new_v7();
    let repository = repository(repository_id, 10);
    let member_worktree = worktree(member_worktree_id, repository_id, 10);
    let outside_worktree = worktree(outside_worktree_id, repository_id, 11);
    let repository_command = JournalCommand::new(
        CommandId::new_v7(),
        vec![
            JournalEventDraft::runtime(
                1,
                CONFIG,
                ALGO,
                JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
            ),
            JournalEventDraft::runtime(
                1,
                CONFIG,
                ALGO,
                JournalPayload::WorktreeInstanceRecorded(Box::new(member_worktree.clone())),
            ),
            JournalEventDraft::runtime(
                1,
                CONFIG,
                ALGO,
                JournalPayload::WorktreeInstanceRecorded(Box::new(outside_worktree.clone())),
            ),
        ],
    )
    .unwrap();
    writer.commit(&repository_command, 1).await.unwrap();

    let mut task = task("membership subset", 2);
    task.scope_memberships = vec![TaskScopeMembership {
        repository_instance_id: Some(repository_id),
        worktree_instance_ids: vec![member_worktree_id],
    }];
    writer
        .commit(&create_task(context(2), task.clone()).unwrap(), 2)
        .await
        .unwrap();
    let mut forged = workstream(task.task_id, "outside membership", 3);
    forged.repository_instance_id = Some(repository_id);
    forged.worktree_instance_ids = vec![outside_worktree_id];
    forged.active_worktree_instance_id = Some(outside_worktree_id);
    let forged_command = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            3,
            CONFIG,
            ALGO,
            JournalPayload::WorkstreamRecorded(Box::new(forged.clone())),
        )],
    )
    .unwrap();
    let before_rows = writer.journal_rows().await.unwrap();
    let before_projection = writer.project().await.unwrap();
    assert_eq!(
        writer.commit(&forged_command, 3).await.unwrap_err(),
        StoreError::InvalidInput
    );
    assert_eq!(writer.journal_rows().await.unwrap(), before_rows);
    assert_eq!(writer.project().await.unwrap(), before_projection);

    let repository_view = RepositoryCurrentView {
        repositories: [(repository_id, repository)].into(),
        worktrees: [
            (member_worktree_id, member_worktree),
            (outside_worktree_id, outside_worktree),
        ]
        .into(),
        ..RepositoryCurrentView::default()
    };
    assert!(derive_active_lineage(&task, &forged, &repository_view).is_err());
    assert!(build_work_identity_relation_rows(&[task], &[forged]).is_err());
}

#[test]
fn typed_material_goal_change_allocates_a_new_workstream() {
    let task = task("task", 1);
    let current = workstream(task.task_id, "old", 2);
    let mut replacement = workstream(task.task_id, "new", 3);
    let replacement_command = replace_workstream_for_material_goal(
        context(3),
        &task,
        &RepositoryCurrentView::default(),
        &current,
        replacement.clone(),
        &["material-goal-decision".into()],
    )
    .unwrap();
    assert_eq!(replacement_command.events().len(), 2);
    replacement.workstream_id = current.workstream_id;
    assert!(
        replace_workstream_for_material_goal(
            context(3),
            &task,
            &RepositoryCurrentView::default(),
            &current,
            replacement,
            &["material-goal-decision".into()],
        )
        .is_err()
    );
    let mut textual = current.clone();
    textual.revision_id = RevisionId::new_v7();
    textual.predecessor_revision_id = Some(current.revision_id);
    textual.workstream_goal = "different text".into();
    textual.source_watermark += 1;
    assert!(
        revise_workstream(
            context(4),
            &task,
            &RepositoryCurrentView::default(),
            &current,
            textual,
            TypedWorkstreamChange::StructuredRevision,
            &["typed-structured-change".into()],
        )
        .is_ok()
    );
}

#[test]
fn correlation_requires_explicit_or_unique_strong_scope_consistent_evidence() {
    let other_task = task("other task", 5);
    let task = task("task", 1);
    let first = workstream(task.task_id, "first", 2);
    let second = workstream(task.task_id, "second", 3);
    let view = WorkIdentityCurrentView {
        frontier: 3,
        tasks: [(task.task_id, task.clone())].into(),
        workstreams: [
            (first.workstream_id, first.clone()),
            (second.workstream_id, second.clone()),
        ]
        .into(),
    };
    let explicit = CorrelationEvidence {
        kind: CorrelationEvidenceKind::ExplicitWorkstream,
        evidence_ref: "explicit".into(),
        candidate_task_ids: Vec::new(),
        candidate_workstream_ids: vec![first.workstream_id],
    };
    assert_eq!(
        resolve_workstream_candidate(&view, CorrelationScope::default(), &[explicit], 4),
        CorrelationResult::Resolved(first.workstream_id)
    );
    let explicit_task = CorrelationEvidence {
        kind: CorrelationEvidenceKind::ExplicitTask,
        evidence_ref: "explicit-task".into(),
        candidate_task_ids: vec![task.task_id],
        candidate_workstream_ids: Vec::new(),
    };
    assert!(matches!(
        resolve_workstream_candidate(
            &WorkIdentityCurrentView {
                frontier: 3,
                tasks: [(task.task_id, task.clone())].into(),
                workstreams: [(first.workstream_id, first.clone())].into(),
            },
            CorrelationScope::default(),
            &[explicit_task],
            4,
        ),
        CorrelationResult::Resolved(id) if id == first.workstream_id
    ));
    let weak = CorrelationEvidence {
        kind: CorrelationEvidenceKind::Session,
        evidence_ref: "session".into(),
        candidate_task_ids: Vec::new(),
        candidate_workstream_ids: vec![first.workstream_id],
    };
    assert!(matches!(
        resolve_workstream_candidate(&view, CorrelationScope::default(), &[weak], 4),
        CorrelationResult::Unresolved(_)
    ));
    let mut conflict = CorrelationEvidence {
        kind: CorrelationEvidenceKind::Patch,
        evidence_ref: "patch".into(),
        candidate_task_ids: Vec::new(),
        candidate_workstream_ids: vec![first.workstream_id, second.workstream_id],
    };
    conflict.candidate_workstream_ids.sort();
    assert!(matches!(
        resolve_workstream_candidate(&view, CorrelationScope::default(), &[conflict], 4),
        CorrelationResult::Unresolved(_)
    ));

    let other = workstream(other_task.task_id, "other stream", 6);
    let conflict_view = WorkIdentityCurrentView {
        frontier: 6,
        tasks: [
            (task.task_id, task.clone()),
            (other_task.task_id, other_task.clone()),
        ]
        .into(),
        workstreams: [
            (first.workstream_id, first.clone()),
            (second.workstream_id, second.clone()),
            (other.workstream_id, other),
        ]
        .into(),
    };
    let explicit_first = CorrelationEvidence {
        kind: CorrelationEvidenceKind::ExplicitWorkstream,
        evidence_ref: "explicit-first".into(),
        candidate_task_ids: Vec::new(),
        candidate_workstream_ids: vec![first.workstream_id],
    };
    let explicit_other_task = CorrelationEvidence {
        kind: CorrelationEvidenceKind::ExplicitTask,
        evidence_ref: "explicit-other-task".into(),
        candidate_task_ids: vec![other_task.task_id],
        candidate_workstream_ids: Vec::new(),
    };
    assert!(matches!(
        resolve_workstream_candidate(
            &conflict_view,
            CorrelationScope::default(),
            &[explicit_first.clone(), explicit_other_task],
            7,
        ),
        CorrelationResult::Unresolved(_)
    ));
    let strong_second = CorrelationEvidence {
        kind: CorrelationEvidenceKind::Patch,
        evidence_ref: "strong-second".into(),
        candidate_task_ids: Vec::new(),
        candidate_workstream_ids: vec![second.workstream_id],
    };
    assert!(matches!(
        resolve_workstream_candidate(
            &conflict_view,
            CorrelationScope::default(),
            &[explicit_first.clone(), strong_second],
            7,
        ),
        CorrelationResult::Unresolved(_)
    ));
    assert!(matches!(
        resolve_workstream_candidate(
            &conflict_view,
            CorrelationScope {
                task_id: Some(other_task.task_id),
                ..CorrelationScope::default()
            },
            &[explicit_first],
            7,
        ),
        CorrelationResult::Unresolved(_)
    ));
}

#[test]
fn provisional_task_never_forms_active_lineage() {
    let mut task = task("task", 1);
    task.identity_confidence = TaskIdentityConfidence::Provisional;
    let workstream = workstream(task.task_id, "stream", 2);
    assert!(derive_active_lineage(&task, &workstream, &RepositoryCurrentView::default()).is_err());
    task.identity_confidence = TaskIdentityConfidence::Explicit;
    let lineage =
        derive_active_lineage(&task, &workstream, &RepositoryCurrentView::default()).unwrap();
    assert_eq!(lineage.task_revision_id, task.revision_id);
    assert_eq!(lineage.workstream_revision_id, workstream.revision_id);
}

#[test]
fn removed_worktree_clears_active_pointer_without_closing_task_or_workstream() {
    let repo = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let mut task = task("removed worktree", 1);
    task.scope_memberships = vec![TaskScopeMembership {
        repository_instance_id: Some(repo),
        worktree_instance_ids: vec![worktree_id],
    }];
    let mut stream = workstream(task.task_id, "stream", 2);
    stream.repository_instance_id = Some(repo);
    stream.worktree_instance_ids = vec![worktree_id];
    stream.active_worktree_instance_id = Some(worktree_id);
    let mut removed = worktree(worktree_id, repo, 1);
    removed.lifecycle = WorktreeLifecycle::Removed;
    removed.current_path = None;
    removed.terminal_event_ref = Some("removed-evidence".into());
    let repository_view = RepositoryCurrentView {
        repositories: [(repo, repository(repo, 1))].into(),
        worktrees: [(worktree_id, removed)].into(),
        ..RepositoryCurrentView::default()
    };
    assert!(derive_active_lineage(&task, &stream, &repository_view).is_err());
    let mut successor = stream.clone();
    successor.revision_id = RevisionId::new_v7();
    successor.predecessor_revision_id = Some(stream.revision_id);
    successor.active_worktree_instance_id = None;
    successor.source_watermark = 3;
    assert!(
        revise_workstream(
            context(3),
            &task,
            &repository_view,
            &stream,
            successor.clone(),
            TypedWorkstreamChange::WorktreeLineage,
            &["worktree-removed".into()],
        )
        .is_ok()
    );
    assert_eq!(task.lifecycle, TaskLifecycle::Active);
    assert_eq!(successor.status, WorkstreamStatus::Active);
    assert_eq!(successor.worktree_instance_ids, vec![worktree_id]);
}

#[tokio::test]
async fn replay_restart_full_rebuild_and_current_rows_are_stable() {
    let temp = TempDir::new().unwrap();
    let root = task("persist", 1);
    let stream = workstream(root.task_id, "persist stream", 2);
    let root_command = create_task(context(1), root.clone()).unwrap();
    let store = temp.path().join("store");
    let mut writer = JournalWriter::open(&store).await.unwrap();
    let committed = writer.commit(&root_command, 1).await.unwrap();
    let replay = writer.commit(&root_command, 2).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.first_seq, committed.first_seq);
    writer
        .commit(
            &create_workstream(
                context(2),
                &root,
                &RepositoryCurrentView::default(),
                stream.clone(),
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();
    let incremental = writer.project().await.unwrap();
    let full = reduce_journal(&writer.journal_rows().await.unwrap()).unwrap();
    assert_eq!(incremental, full);
    drop(writer);
    let writer = JournalWriter::open(&store).await.unwrap();
    assert_eq!(writer.project().await.unwrap(), full);
    let rows = writer.object_rows().await.unwrap();
    assert!(rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("task")
            && row.current_revision_id.as_deref() == Some(&root.revision_id.to_string())
    }));
    assert!(rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("workstream")
            && row.current_revision_id.as_deref() == Some(&stream.revision_id.to_string())
    }));
    assert_eq!(writer.table_names().await.unwrap().len(), 4);
}

#[test]
fn ids_are_uuid_v7_and_relation_builder_is_pure() {
    let before = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let task = task("relations", 1);
    let stream = workstream(task.task_id, "relations stream", 2);
    let revision = RevisionId::new_v7();
    let after = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    for uuid in [
        task.task_id.as_uuid(),
        stream.workstream_id.as_uuid(),
        revision.as_uuid(),
    ] {
        let (seconds, nanos) = uuid.get_timestamp().unwrap().to_unix();
        let millis = u128::from(seconds) * 1000 + u128::from(nanos) / 1_000_000;
        assert!((before..=after).contains(&millis));
    }
    let relations =
        build_work_identity_relation_rows(&[task], &[stream]).expect("pure relation rows");
    assert!(
        relations
            .iter()
            .any(|row| { row.kind == WorkIdentityRelationKind::TaskContainsWorkstream })
    );
}
