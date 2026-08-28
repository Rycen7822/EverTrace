//! S11 Repository/Worktree identity, snapshot, transition and integration
//! proofs against real Git repositories on a real filesystem.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    sync::{Condvar, Mutex},
    time::SystemTime,
};

use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, EffectRole, EvidenceByteRange, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, ScopeEffectClaim,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, RepositoryId, WorktreeId, WorktreeSnapshotId},
    repository::{
        GitOperation, IntegrationKind, LineageAssessment, ProbeUnavailableReason,
        REMOTE_FINGERPRINT_PREFIX, RepositoryInstance, SnapshotCaptureStatus, TransitionKind,
        WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
};
use evertrace_engine::{
    PhysicalNormalizer,
    repository::{
        GitOid, GitProbeEvidence, HostTrustDecision, IntegrationEvidence, ProbeField, ProbeLimits,
        ProbeOmission, RepositoryProbeError, RepositoryResolution, RepositoryResolveError,
        RepositoryResolveInput, ResolutionKind, correct_transition,
        probe_is_ancestor as engine_probe_is_ancestor,
        probe_patch_equivalence as engine_probe_patch_equivalence,
        probe_repository as engine_probe_repository, remote_fingerprint, resolve_integration,
        resolve_repository,
    },
};
use evertrace_store::{
    CompatibilityStore, DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft,
    JournalPayload, JournalWriter, OBJECTS_TABLE, SourceIngestWatermark, StoreError,
    objects_schema, reduce_journal,
    relations::{PhysicalRelationKind, build_physical_relation_rows},
    repository::RepositoryCurrentView,
};
use tempfile::TempDir;

const CONFIG_HASH: [u8; 32] = [0x42; 32];
const ALGO: &str = "s11-repository-v1";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
struct GitGateState {
    active_children: usize,
    reopening: bool,
}

static GIT_CHILD_GATE: (Mutex<GitGateState>, Condvar) = (
    Mutex::new(GitGateState {
        active_children: 0,
        reopening: false,
    }),
    Condvar::new(),
);

struct GitChildGate;

impl Drop for GitChildGate {
    fn drop(&mut self) {
        let (state, changed) = &GIT_CHILD_GATE;
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_children -= 1;
        changed.notify_all();
    }
}

fn enter_git_child() -> GitChildGate {
    let (state, changed) = &GIT_CHILD_GATE;
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while state.reopening {
        state = changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    state.active_children += 1;
    GitChildGate
}

struct GitReopenGate;

impl Drop for GitReopenGate {
    fn drop(&mut self) {
        let (state, changed) = &GIT_CHILD_GATE;
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.reopening = false;
        changed.notify_all();
    }
}

fn enter_reopen() -> GitReopenGate {
    let (state, changed) = &GIT_CHILD_GATE;
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while state.reopening || state.active_children != 0 {
        state = changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    state.reopening = true;
    GitReopenGate
}

// ---------------------------------------------------------------------------
// Git fixture helpers (the only place tests may mutate Git state)
// ---------------------------------------------------------------------------

fn git(dir: &Path, args: &[&str]) -> String {
    let _child_gate = enter_git_child();
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=EverTraceTest",
            "-c",
            "user.email=evertrace-test@example.invalid",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git -C {dir:?} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn probe_repository(
    candidate_path: &Path,
    trust: HostTrustDecision,
    evidence_refs: &[String],
    occurred_at_us: i64,
    limits: &ProbeLimits,
    known_admin_paths: &[String],
    known_head_oids: &[GitOid],
) -> Result<GitProbeEvidence, RepositoryProbeError> {
    let _child_gate = enter_git_child();
    engine_probe_repository(
        candidate_path,
        trust,
        evidence_refs,
        occurred_at_us,
        limits,
        known_admin_paths,
        known_head_oids,
    )
}

fn probe_is_ancestor(
    repository_path: &Path,
    ancestor: &GitOid,
    descendant: &GitOid,
    limits: &ProbeLimits,
) -> Result<bool, RepositoryProbeError> {
    let _child_gate = enter_git_child();
    engine_probe_is_ancestor(repository_path, ancestor, descendant, limits)
}

fn probe_patch_equivalence(
    repository_path: &Path,
    base_a: &GitOid,
    tip_a: &GitOid,
    base_b: &GitOid,
    tip_b: &GitOid,
    limits: &ProbeLimits,
) -> Result<Option<String>, RepositoryProbeError> {
    let _child_gate = enter_git_child();
    engine_probe_patch_equivalence(repository_path, base_a, tip_a, base_b, tip_b, limits)
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap()
}

fn init_repo(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "-q", "-b", "main"]);
    commit_file(dir, "a.txt", "a")
}

fn commit_file(dir: &Path, name: &str, content: &str) -> String {
    std::fs::write(dir.join(name), content).unwrap();
    git(dir, &["add", name]);
    git(dir, &["commit", "-q", "-m", &format!("add {name}")]);
    git(dir, &["rev-parse", "HEAD"])
}

fn head_oid(dir: &Path) -> GitOid {
    GitOid::parse(&git(dir, &["rev-parse", "HEAD"])).unwrap()
}

// ---------------------------------------------------------------------------
// Store/probe harness: project -> view -> probe -> resolve -> commit
// ---------------------------------------------------------------------------

struct Refresh {
    resolution: RepositoryResolution,
    command: Option<JournalCommand>,
    frontier: u64,
}

struct Harness {
    temp: TempDir,
    writer: JournalWriter,
    clock: i64,
}

impl Harness {
    async fn open() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("store");
        let writer = JournalWriter::open(&root).await.unwrap();
        Self {
            temp,
            writer,
            clock: 0,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.temp.path().join(name)
    }

    fn tick(&mut self) -> i64 {
        self.clock += 1;
        self.clock
    }

    async fn view(&mut self) -> RepositoryCurrentView {
        let snapshot = self.writer.project().await.unwrap();
        RepositoryCurrentView::from_snapshot(&snapshot).unwrap()
    }

    async fn refresh(&mut self, path: &Path) -> Refresh {
        self.refresh_with(
            path,
            HostTrustDecision::Trusted,
            ProbeLimits::default(),
            None,
        )
        .await
    }

    async fn refresh_with(
        &mut self,
        path: &Path,
        trust: HostTrustDecision,
        limits: ProbeLimits,
        derived_from_hint: Option<RepositoryId>,
    ) -> Refresh {
        let occurred = self.tick();
        let view = self.view().await;
        let refs = vec![format!("probe-evidence-{occurred}")];
        let known_heads = known_head_oids(&view);
        let evidence = probe_repository(
            path,
            trust,
            &refs,
            occurred,
            &limits,
            &view.known_admin_paths(),
            &known_heads,
        )
        .unwrap();
        let resolution = match resolve_repository(&RepositoryResolveInput {
            view: &view,
            evidence: &evidence,
            derived_from_hint,
        }) {
            Ok(resolution) => resolution,
            Err(error) => panic!("resolve failed: {error:?}\nevidence: {evidence:#?}"),
        };
        let command = resolution
            .journal_command(occurred, CONFIG_HASH, ALGO)
            .unwrap();
        if let Some(command) = &command {
            self.writer
                .commit_if_frontier(command, occurred, view.frontier)
                .await
                .unwrap();
        }
        Refresh {
            resolution,
            command,
            frontier: view.frontier,
        }
    }

    async fn commit_integration(&mut self, evidence: IntegrationEvidence) -> RepositoryResolution {
        let occurred = self.tick();
        let view = self.view().await;
        let resolution = resolve_integration(&view, &evidence).unwrap();
        let command = resolution
            .journal_command(occurred, CONFIG_HASH, ALGO)
            .unwrap();
        if let Some(command) = &command {
            self.writer
                .commit_if_frontier(command, occurred, view.frontier)
                .await
                .unwrap();
        }
        resolution
    }
}

fn only_repository(view: &RepositoryCurrentView) -> &RepositoryInstance {
    assert_eq!(view.repositories.len(), 1);
    view.repositories.values().next().unwrap()
}

/// Historical HEAD OIDs from the current view, handed to the probe so
/// continuity can be proven by positive ancestry evidence.
fn known_head_oids(view: &RepositoryCurrentView) -> Vec<GitOid> {
    view.snapshots
        .values()
        .filter_map(|snapshot| snapshot.head_oid.clone())
        .filter_map(|oid| GitOid::parse(&oid).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn worktree_at<'a>(view: &'a RepositoryCurrentView, path: &Path) -> Option<&'a WorktreeInstance> {
    let path = path.to_string_lossy().into_owned();
    view.worktrees
        .values()
        .find(|worktree| worktree.current_path.as_deref() == Some(path.as_str()))
        .or_else(|| {
            view.worktrees.values().find(|worktree| {
                worktree
                    .path_history
                    .last()
                    .is_some_and(|entry| entry.path == path)
            })
        })
}

fn main_worktree(view: &RepositoryCurrentView, repository_id: RepositoryId) -> &WorktreeInstance {
    view.worktrees
        .values()
        .find(|worktree| {
            worktree.repository_instance_id == repository_id && worktree.kind == WorktreeKind::Main
        })
        .unwrap()
}

fn current_snapshot_id(
    view: &RepositoryCurrentView,
    worktree: &WorktreeInstance,
) -> WorktreeSnapshotId {
    let id = worktree.current_snapshot_id.unwrap();
    assert!(view.snapshots.contains_key(&id));
    id
}

// ---------------------------------------------------------------------------
// Identity tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repository_move_keeps_identity_and_extends_path_history() {
    let mut harness = Harness::open().await;
    let before = harness.path("repo-before");
    init_repo(&before);
    let first = harness.refresh(&canonical(&before)).await;
    assert_eq!(first.resolution.kind, Some(ResolutionKind::Create));
    let view = harness.view().await;
    let repository = only_repository(&view).clone();
    let worktree = main_worktree(&view, repository.repository_id).clone();
    assert_eq!(repository.repository_revision, 1);
    assert_eq!(repository.path_history.len(), 1);

    let after = harness.path("repo-after");
    std::fs::rename(&before, &after).unwrap();
    let moved = harness.refresh(&canonical(&after)).await;
    assert_eq!(moved.resolution.kind, Some(ResolutionKind::Successor));
    assert_eq!(moved.resolution.detail.as_deref(), Some("repository_moved"));

    let view = harness.view().await;
    let repository = only_repository(&view);
    assert_eq!(repository.repository_revision, 2);
    assert_eq!(repository.predecessor_revision, Some(1));
    assert_eq!(repository.path_history.len(), 2);
    assert_eq!(
        repository.path_history.last().unwrap().path,
        canonical(&after).to_string_lossy()
    );
    assert!(
        moved
            .resolution
            .transitions
            .iter()
            .any(
                |transition| transition.kind == TransitionKind::RepositoryMoved
                    && transition.lineage_assessment == LineageAssessment::Proven
            )
    );

    // The main worktree keeps its instance id across the move.
    let worktree_after = view.worktrees.get(&worktree.worktree_instance_id).unwrap();
    assert_eq!(view.worktrees.len(), 1);
    assert_eq!(worktree_after.worktree_revision, 2);
    assert_eq!(worktree_after.lifecycle, WorktreeLifecycle::Active);
    assert_eq!(worktree_after.path_history.len(), 2);
    assert_eq!(
        worktree_after.path_history.last().unwrap().path,
        canonical(&after).to_string_lossy()
    );
    assert!(
        moved
            .resolution
            .transitions
            .iter()
            .any(
                |transition| transition.kind == TransitionKind::WorktreeRepaired
                    && transition.from_worktree_instance_id == worktree.worktree_instance_id
            )
    );

    // A no-op probe after the move produces no further payloads.
    let quiet = harness.refresh(&canonical(&after)).await;
    assert_eq!(quiet.resolution.kind, Some(ResolutionKind::NoDelta));
    assert!(quiet.command.is_none());
}

#[tokio::test]
async fn copies_reclones_and_reinit_create_new_repository_instances() {
    let mut harness = Harness::open().await;
    let origin = harness.path("origin");
    init_repo(&origin);
    harness.refresh(&canonical(&origin)).await;
    let origin_id = only_repository(&harness.view().await).repository_id;

    // `cp -a` copy: derived_from lineage only, never the same instance.
    let copied = harness.path("copied");
    let status = Command::new("cp")
        .arg("-a")
        .arg(&origin)
        .arg(&copied)
        .status()
        .unwrap();
    assert!(status.success());
    let copy = harness
        .refresh_with(
            &canonical(&copied),
            HostTrustDecision::Trusted,
            ProbeLimits::default(),
            Some(origin_id),
        )
        .await;
    assert_eq!(copy.resolution.kind, Some(ResolutionKind::Create));
    let copied_id = copy.resolution.repositories[0].repository_id;
    assert_ne!(copied_id, origin_id);
    assert_eq!(
        copy.resolution.repositories[0].derived_from,
        Some(origin_id)
    );
    assert!(
        copy.resolution
            .transitions
            .iter()
            .any(
                |transition| transition.kind == TransitionKind::RepositoryCopied
                    && transition.lineage_assessment == LineageAssessment::Partial
            )
    );

    // `git clone file://`: new instance, remote fingerprint recorded.
    let cloned = harness.path("cloned");
    git(
        harness.temp.path(),
        &[
            "clone",
            "-q",
            &format!("file://{}", canonical(&origin).display()),
            cloned.to_str().unwrap(),
        ],
    );
    let clone = harness
        .refresh_with(
            &canonical(&cloned),
            HostTrustDecision::Trusted,
            ProbeLimits::default(),
            Some(origin_id),
        )
        .await;
    let cloned_repo = &clone.resolution.repositories[0];
    assert_ne!(cloned_repo.repository_id, origin_id);
    assert_ne!(cloned_repo.repository_id, copied_id);
    assert_eq!(cloned_repo.derived_from, Some(origin_id));
    assert!(
        cloned_repo
            .remote_fingerprints
            .iter()
            .any(|fingerprint| fingerprint.starts_with(REMOTE_FINGERPRINT_PREFIX))
    );

    // Re-init at the same path: different filesystem identity, therefore a
    // new instance with derived_from pointing at the previous occupant. The
    // old directory is moved aside (not deleted) so inode reuse cannot alias
    // the two instances.
    let moved_aside = harness.path("origin-away");
    std::fs::rename(&origin, &moved_aside).unwrap();
    init_repo(&origin);
    let reinit = harness.refresh(&canonical(&origin)).await;
    assert_eq!(reinit.resolution.kind, Some(ResolutionKind::Create));
    let reinit_repo = &reinit.resolution.repositories[0];
    assert_ne!(reinit_repo.repository_id, origin_id);
    assert_eq!(reinit_repo.derived_from, Some(origin_id));

    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 4);
}

#[tokio::test]
async fn linked_worktree_move_prune_and_recreate_follow_identity_rules() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let linked = canonical(&harness.path("linked"));
    harness.refresh(&repo).await;

    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let linked_id = worktree_at(&view, &linked).unwrap().worktree_instance_id;
    assert_eq!(view.worktrees.len(), 2);
    assert_eq!(
        worktree_at(&view, &linked).unwrap().kind,
        WorktreeKind::Linked
    );

    // `git worktree move`: same instance, path history extended.
    git(
        &repo,
        &[
            "worktree",
            "move",
            linked.to_str().unwrap(),
            harness.path("linked2").to_str().unwrap(),
        ],
    );
    let linked2 = canonical(&harness.path("linked2"));
    let moved = harness.refresh(&repo).await;
    let view = harness.view().await;
    let linked_after_move = view.worktrees.get(&linked_id).unwrap();
    assert_eq!(view.worktrees.len(), 2);
    assert_eq!(linked_after_move.worktree_revision, 2);
    assert_eq!(linked_after_move.lifecycle, WorktreeLifecycle::Active);
    assert_eq!(
        linked_after_move.current_path.as_deref(),
        Some(linked2.to_string_lossy().as_ref())
    );
    assert!(
        moved
            .resolution
            .transitions
            .iter()
            .any(|transition| transition.kind == TransitionKind::PathMoved
                && transition.from_worktree_instance_id == linked_id)
    );

    // rm -rf makes the entry prunable: missing, not removed.
    std::fs::remove_dir_all(&linked2).unwrap();
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let linked_missing = view.worktrees.get(&linked_id).unwrap();
    assert_eq!(linked_missing.lifecycle, WorktreeLifecycle::Missing);

    // prune terminates the instance for good.
    git(&repo, &["worktree", "prune"]);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let linked_pruned = view.worktrees.get(&linked_id).unwrap();
    assert_eq!(linked_pruned.lifecycle, WorktreeLifecycle::Pruned);
    assert!(linked_pruned.terminal_event_ref.is_some());
    assert!(linked_pruned.current_path.is_none());

    // Re-adding at the same path creates a new instance linked only by
    // recreated_from.
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            linked2.to_str().unwrap(),
            "-b",
            "feature2",
        ],
    );
    let recreated = harness.refresh(&repo).await;
    let view = harness.view().await;
    assert_eq!(view.worktrees.len(), 3);
    let new_linked = worktree_at(&view, &linked2).unwrap();
    assert_ne!(new_linked.worktree_instance_id, linked_id);
    assert_eq!(new_linked.worktree_revision, 1);
    assert_eq!(
        new_linked.recreated_from_worktree_instance_id,
        Some(linked_id)
    );
    assert!(
        recreated
            .resolution
            .transitions
            .iter()
            .any(
                |transition| transition.kind == TransitionKind::WorktreeRecreated
                    && transition.from_worktree_instance_id == linked_id
                    && transition.to_worktree_instance_id == new_linked.worktree_instance_id
            )
    );
    let _ = repository_id;
}

#[tokio::test]
async fn branch_switch_detach_and_commit_only_create_snapshots_and_transitions() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    let base = init_repo(&repo);
    let repo = canonical(&repo);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let worktree_id = main_worktree(&view, repository_id).worktree_instance_id;
    let first_snapshot = current_snapshot_id(&view, main_worktree(&view, repository_id));

    // Branch switch.
    git(&repo, &["checkout", "-q", "-b", "topic"]);
    let switched = harness.refresh(&repo).await;
    assert!(
        switched
            .resolution
            .transitions
            .iter()
            .any(
                |transition| transition.kind == TransitionKind::BranchSwitched
                    && transition.from_snapshot_id == Some(first_snapshot)
            )
    );

    // Detach.
    git(&repo, &["checkout", "-q", "--detach"]);
    let detached = harness.refresh(&repo).await;
    assert!(
        detached
            .resolution
            .transitions
            .iter()
            .any(|transition| transition.kind == TransitionKind::DetachedOrAttached)
    );
    let view = harness.view().await;
    let snapshot = view
        .snapshots
        .get(&current_snapshot_id(
            &view,
            view.worktrees.get(&worktree_id).unwrap(),
        ))
        .unwrap();
    assert!(snapshot.detached_head);
    assert!(snapshot.branch_ref.is_none());

    // Commit while detached: head advanced.
    commit_file(&repo, "b.txt", "b");
    let committed = harness.refresh(&repo).await;
    assert!(
        committed
            .resolution
            .transitions
            .iter()
            .any(|transition| transition.kind == TransitionKind::HeadAdvanced)
    );

    // Merge in progress: git_operation is snapshot state, not a transition.
    git(&repo, &["checkout", "-q", "-b", "other", &base]);
    commit_file(&repo, "a.txt", "other");
    git(&repo, &["checkout", "-q", "main"]);
    commit_file(&repo, "a.txt", "main");
    let merge = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args([
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@e",
            "merge",
            "--no-ff",
            "-m",
            "m",
            "other",
        ])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        !merge.status.success(),
        "conflicting merge must stop mid-merge"
    );
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let worktree = view.worktrees.get(&worktree_id).unwrap();
    let snapshot = view
        .snapshots
        .get(&worktree.current_snapshot_id.unwrap())
        .unwrap();
    assert_eq!(snapshot.git_operation, GitOperation::Merge);

    // Identity never changed across all of the above.
    assert_eq!(view.repositories.len(), 1);
    assert_eq!(view.worktrees.len(), 1);
    assert_eq!(
        view.worktrees.get(&worktree_id).unwrap().lifecycle,
        WorktreeLifecycle::Active
    );
}

// ---------------------------------------------------------------------------
// Lifecycle safety and degraded evidence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_is_not_removed_and_terminal_worktrees_never_revive() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let linked = canonical(&harness.path("linked"));
    harness.refresh(&repo).await;
    let linked_id = worktree_at(&harness.view().await, &linked)
        .unwrap()
        .worktree_instance_id;

    // Directly probing the deleted path: missing, never removed.
    std::fs::remove_dir_all(&linked).unwrap();
    let missing = harness.refresh(&linked).await;
    assert!(
        missing
            .resolution
            .transitions
            .iter()
            .any(|transition| transition.kind == TransitionKind::WorktreeMissing)
    );
    let view = harness.view().await;
    let worktree = view.worktrees.get(&linked_id).unwrap();
    assert_eq!(worktree.lifecycle, WorktreeLifecycle::Missing);
    assert!(worktree.terminal_event_ref.is_none());
    assert!(worktree.current_path.is_some());

    // Confirmed admin-record removal terminates the instance.
    git(&repo, &["worktree", "prune"]);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let worktree = view.worktrees.get(&linked_id).unwrap();
    assert!(worktree.lifecycle.is_terminal());
    assert!(worktree.terminal_event_ref.is_some());
    assert!(worktree.current_path.is_none());

    // A hand-crafted revival payload is rejected twice: the lifecycle closure
    // rejects the successor, and no journal row is appended.
    let terminal = worktree.clone();
    let mut revival = terminal.clone();
    revival.worktree_revision = terminal.worktree_revision + 1;
    revival.predecessor_revision = Some(terminal.worktree_revision);
    revival.lifecycle = WorktreeLifecycle::Active;
    revival.current_path = Some(linked.to_string_lossy().into_owned());
    revival.terminal_event_ref = None;
    revival.validate().unwrap();
    let occurred = harness.tick();
    let command = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            occurred,
            CONFIG_HASH,
            ALGO,
            JournalPayload::WorktreeInstanceRecorded(Box::new(revival)),
        )],
    )
    .unwrap();
    let rows_before = harness.writer.journal_rows().await.unwrap().len();
    assert!(harness.writer.commit(&command, occurred).await.is_err());
    let view = harness.view().await;
    assert!(
        view.worktrees
            .get(&linked_id)
            .unwrap()
            .lifecycle
            .is_terminal()
    );
    assert_eq!(
        harness.writer.journal_rows().await.unwrap().len(),
        rows_before
    );
}

#[tokio::test]
async fn unborn_empty_repository_resolves_create_then_no_delta_across_restart() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    let repo = canonical(&repo);

    // First refresh establishes the instance on an unborn HEAD.
    let first = harness.refresh(&repo).await;
    assert_eq!(first.resolution.kind, Some(ResolutionKind::Create));
    let view = harness.view().await;
    let repository = only_repository(&view).clone();
    let worktree = main_worktree(&view, repository.repository_id);
    let snapshot = view
        .snapshots
        .get(&worktree.current_snapshot_id.unwrap())
        .unwrap();
    assert!(snapshot.head_oid.is_none());
    assert_eq!(snapshot.branch_ref.as_deref(), Some("refs/heads/main"));

    // Second refresh: narrow unborn continuity selects the same instance and
    // is a stable no-delta — no new objects, frontier untouched.
    let frontier = view.frontier;
    let second = harness.refresh(&repo).await;
    assert_eq!(second.resolution.kind, Some(ResolutionKind::NoDelta));
    assert!(second.command.is_none());
    let view = harness.view().await;
    assert_eq!(view.frontier, frontier);
    assert_eq!(view.repositories.len(), 1);
    assert_eq!(view.worktrees.len(), 1);
    assert_eq!(view.snapshots.len(), 1);

    // After a restart the rebuilt view resolves identically.
    let store_root = harness.temp.path().join("store");
    harness.writer = {
        let _reopen_gate = enter_reopen();
        drop(harness.writer);
        JournalWriter::open(&store_root).await.unwrap()
    };
    let third = harness.refresh(&repo).await;
    assert_eq!(third.resolution.kind, Some(ResolutionKind::NoDelta));
    assert!(third.command.is_none());
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 1);
    assert_eq!(
        only_repository(&view).repository_id,
        repository.repository_id
    );
    assert_eq!(view.frontier, frontier);
}

#[tokio::test]
async fn repeated_path_missing_is_idempotent() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let linked = canonical(&harness.path("linked"));
    harness.refresh(&repo).await;
    let linked_id = worktree_at(&harness.view().await, &linked)
        .unwrap()
        .worktree_instance_id;

    // First absence: missing successor, exactly once.
    std::fs::remove_dir_all(&linked).unwrap();
    let first = harness.refresh(&linked).await;
    assert_eq!(first.resolution.kind, Some(ResolutionKind::Successor));
    assert!(
        first
            .resolution
            .transitions
            .iter()
            .any(|transition| transition.kind == TransitionKind::WorktreeMissing)
    );
    let view = harness.view().await;
    assert_eq!(
        view.worktrees.get(&linked_id).unwrap().lifecycle,
        WorktreeLifecycle::Missing
    );
    let journal_rows = harness.writer.journal_rows().await.unwrap().len();
    let object_rows = harness.writer.object_rows().await.unwrap().len();
    let frontier = view.frontier;

    // Repeated absence is not a new fact: no revision, no second transition,
    // journal, objects and frontier all stay put.
    let second = harness.refresh(&linked).await;
    assert_eq!(second.resolution.kind, Some(ResolutionKind::NoDelta));
    assert!(second.command.is_none());
    assert_eq!(
        harness.writer.journal_rows().await.unwrap().len(),
        journal_rows
    );
    assert_eq!(
        harness.writer.object_rows().await.unwrap().len(),
        object_rows
    );
    let view = harness.view().await;
    assert_eq!(view.frontier, frontier);
    let worktree = view.worktrees.get(&linked_id).unwrap();
    assert_eq!(worktree.lifecycle, WorktreeLifecycle::Missing);
    assert_eq!(worktree.worktree_revision, 2);
    assert_eq!(
        view.transitions
            .values()
            .filter(|transition| transition.kind == TransitionKind::WorktreeMissing)
            .count(),
        1
    );
}

#[tokio::test]
async fn unavailable_probes_yield_path_hint_without_objects() {
    let mut harness = Harness::open().await;

    fn assert_path_hint_without_objects(
        refresh: &Refresh,
        path: &Path,
        reason: ProbeUnavailableReason,
    ) {
        let resolution = &refresh.resolution;
        assert_eq!(resolution.kind, Some(ResolutionKind::Unavailable));
        assert!(resolution.repositories.is_empty());
        assert!(resolution.worktrees.is_empty());
        assert!(resolution.snapshots.is_empty());
        assert!(resolution.transitions.is_empty());
        assert!(resolution.integrations.is_empty());
        assert!(refresh.command.is_none());
        let hint = resolution.path_hint.as_ref().expect("path hint present");
        assert_eq!(hint.path, path.to_string_lossy().as_ref());
        assert_eq!(hint.reason, reason);
        assert!(!hint.evidence_refs.is_empty());
    }

    // Non-Git directory.
    let plain = harness.path("plain");
    std::fs::create_dir_all(&plain).unwrap();
    let plain = canonical(&plain);
    let nongit = harness.refresh(&plain).await;
    assert_path_hint_without_objects(&nongit, &plain, ProbeUnavailableReason::NonGit);

    // Corrupt admin metadata.
    let corrupt = harness.path("corrupt");
    init_repo(&corrupt);
    let corrupt = canonical(&corrupt);
    std::fs::write(corrupt.join(".git/HEAD"), "not-a-ref\n").unwrap();
    let corrupted = harness.refresh(&corrupt).await;
    assert_path_hint_without_objects(
        &corrupted,
        &corrupt,
        ProbeUnavailableReason::CorruptAdminMetadata,
    );

    // Trust denied: no Git process is spawned at all.
    let untrusted = harness.path("untrusted");
    init_repo(&untrusted);
    let untrusted = canonical(&untrusted);
    let denied = harness
        .refresh_with(
            &untrusted,
            HostTrustDecision::Untrusted,
            ProbeLimits::default(),
            None,
        )
        .await;
    assert_path_hint_without_objects(&denied, &untrusted, ProbeUnavailableReason::TrustDenied);

    // Permission denied (or an equivalent git-level refusal) never fabricates
    // identity either.
    let denied_path = harness.path("denied");
    init_repo(&denied_path);
    let denied_path = canonical(&denied_path);
    let metadata = std::fs::metadata(&denied_path).unwrap();
    let mut permissions = metadata.permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o000);
    std::fs::set_permissions(&denied_path, permissions).unwrap();
    let refused = harness.refresh(&denied_path).await;
    let mut permissions = std::fs::metadata(&denied_path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&denied_path, permissions).unwrap();
    assert!(refused.resolution.repositories.is_empty());
    assert!(refused.resolution.worktrees.is_empty());
    assert!(refused.resolution.snapshots.is_empty());
    assert!(refused.resolution.transitions.is_empty());
    assert!(refused.resolution.integrations.is_empty());
    assert!(refused.command.is_none());
    let hint = refused.resolution.path_hint.as_ref().unwrap();
    assert_eq!(hint.path, denied_path.to_string_lossy().as_ref());
    assert_eq!(hint.reason, ProbeUnavailableReason::PermissionDenied);

    // Re-probing the same path with the same reason still records nothing.
    let again = harness.refresh(&plain).await;
    assert_path_hint_without_objects(&again, &plain, ProbeUnavailableReason::NonGit);

    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 0);
    assert!(view.worktrees.is_empty());
    assert!(view.snapshots.is_empty());
    assert!(view.transitions.is_empty());
    assert!(view.integrations.is_empty());
}

#[tokio::test]
async fn snapshot_capture_status_tracks_completeness() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let snapshot = view
        .snapshots
        .get(&current_snapshot_id(
            &view,
            main_worktree(&view, repository_id),
        ))
        .unwrap();
    assert_eq!(snapshot.capture_status, SnapshotCaptureStatus::Complete);
    assert!(snapshot.omission_reasons.is_empty());

    // Partial: untracked manifest exceeds the probe budget.
    std::fs::write(repo.join("untracked-a"), "a").unwrap();
    std::fs::write(repo.join("untracked-b"), "b").unwrap();
    let limits = ProbeLimits {
        max_untracked_paths: 1,
        ..ProbeLimits::default()
    };
    harness
        .refresh_with(&repo, HostTrustDecision::Trusted, limits, None)
        .await;
    let view = harness.view().await;
    let worktree = main_worktree(&view, repository_id);
    let snapshot = view
        .snapshots
        .get(&worktree.current_snapshot_id.unwrap())
        .unwrap();
    assert_eq!(snapshot.capture_status, SnapshotCaptureStatus::Partial);
    assert!(
        snapshot
            .omission_reasons
            .iter()
            .any(|omission| omission.reason == ProbeUnavailableReason::OutputLimitExceeded)
    );

    // Unavailable: corrupt admin metadata on a known worktree records no
    // object at all; the current-snapshot pointer stays untouched.
    let pointer_before = worktree.current_snapshot_id.unwrap();
    let snapshots_before = view.snapshots.len();
    std::fs::write(repo.join(".git/HEAD"), "not-a-ref\n").unwrap();
    let corrupted = harness.refresh(&repo).await;
    assert_eq!(corrupted.resolution.kind, Some(ResolutionKind::Ambiguous));
    assert!(corrupted.resolution.repositories.is_empty());
    assert!(corrupted.resolution.worktrees.is_empty());
    assert!(corrupted.resolution.snapshots.is_empty());
    assert!(corrupted.resolution.transitions.is_empty());
    assert!(corrupted.resolution.integrations.is_empty());
    assert!(corrupted.command.is_none());
    let view = harness.view().await;
    let worktree = view.worktrees.get(&worktree.worktree_instance_id).unwrap();
    assert_eq!(worktree.current_snapshot_id, Some(pointer_before));
    assert_eq!(view.snapshots.len(), snapshots_before);
    assert!(
        view.snapshots
            .values()
            .all(|snapshot| snapshot.capture_status != SnapshotCaptureStatus::Unavailable)
    );
}

// ---------------------------------------------------------------------------
// Fresh UUIDv7 identity allocation
// ---------------------------------------------------------------------------

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

macro_rules! v7_millis {
    ($id:expr) => {{
        let (secs, nanos) = $id
            .as_uuid()
            .get_timestamp()
            .expect("object IDs are UUIDv7")
            .to_unix();
        u128::from(secs) * 1000 + u128::from(nanos) / 1_000_000
    }};
}

fn assert_allocated_within_ms(id_ms: u128, before_ms: u128, after_ms: u128) {
    assert!(
        before_ms <= id_ms && id_ms <= after_ms,
        "id timestamp {id_ms} outside [{before_ms}, {after_ms}]"
    );
}

#[tokio::test]
async fn resolving_identical_evidence_twice_allocates_distinct_fresh_v7_ids() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    let occurred = harness.tick();
    let view = harness.view().await;
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    let resolve = |view: &RepositoryCurrentView| {
        resolve_repository(&RepositoryResolveInput {
            view,
            evidence: &evidence,
            derived_from_hint: None,
        })
        .unwrap()
    };
    let first = resolve(&view);
    let second = resolve(&view);
    assert_eq!(first.kind, Some(ResolutionKind::Create));
    assert_eq!(second.kind, Some(ResolutionKind::Create));
    // Identical (view, evidence) input still allocates real random v7 IDs.
    assert_ne!(
        first.repositories[0].repository_id,
        second.repositories[0].repository_id
    );
    assert_ne!(
        first.worktrees[0].worktree_instance_id,
        second.worktrees[0].worktree_instance_id
    );
    assert_ne!(
        first.snapshots[0].worktree_snapshot_id,
        second.snapshots[0].worktree_snapshot_id
    );
    for repository in first.repositories.iter().chain(&second.repositories) {
        repository.validate().unwrap();
    }
    for worktree in first.worktrees.iter().chain(&second.worktrees) {
        worktree.validate().unwrap();
    }
    for snapshot in first.snapshots.iter().chain(&second.snapshots) {
        snapshot.validate().unwrap();
    }
}

#[tokio::test]
async fn fresh_v7_ids_carry_their_allocation_time() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);

    let before = now_millis();
    let created = harness.refresh(&repo).await;
    let after = now_millis();
    assert_allocated_within_ms(
        v7_millis!(created.resolution.repositories[0].repository_id),
        before,
        after,
    );
    assert_allocated_within_ms(
        v7_millis!(created.resolution.worktrees[0].worktree_instance_id),
        before,
        after,
    );
    assert_allocated_within_ms(
        v7_millis!(created.resolution.snapshots[0].worktree_snapshot_id),
        before,
        after,
    );

    commit_file(&repo, "b.txt", "b");
    let before = now_millis();
    let advanced = harness.refresh(&repo).await;
    let after = now_millis();
    let transition = advanced
        .resolution
        .transitions
        .iter()
        .find(|transition| transition.kind == TransitionKind::HeadAdvanced)
        .unwrap();
    assert_allocated_within_ms(v7_millis!(transition.worktree_transition_id), before, after);

    // Integration events and their transitions also allocate fresh v7 IDs.
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let linked = canonical(&harness.path("linked"));
    commit_file(&linked, "feature.txt", "feature");
    harness.refresh(&repo).await;
    harness.refresh(&linked).await;
    git(&repo, &["merge", "-q", "--ff-only", "feature"]);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let source = worktree_at(&view, &linked).unwrap().clone();
    let destination = main_worktree(&view, repository_id).clone();
    let before = now_millis();
    let resolution = harness
        .commit_integration(IntegrationEvidence {
            source_worktree_instance_id: source.worktree_instance_id,
            destination_worktree_instance_id: destination.worktree_instance_id,
            source_snapshot_id: source.current_snapshot_id.unwrap(),
            destination_snapshot_id: destination.current_snapshot_id.unwrap(),
            kind: IntegrationKind::FastForward,
            ancestry: Some(
                probe_is_ancestor(
                    &repo,
                    &head_oid(&linked),
                    &head_oid(&repo),
                    &ProbeLimits::default(),
                )
                .unwrap(),
            ),
            ancestry_evidence_ref: Some("ancestry-ts".into()),
            host_event_ref: Some("host-ts".into()),
            patch_equivalence_refs: Vec::new(),
            conflict_resolution_detected: false,
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec!["integration-ts".into()],
            occurred_at_us: 0,
        })
        .await;
    let after = now_millis();
    assert_allocated_within_ms(
        v7_millis!(resolution.integrations[0].integration_event_id),
        before,
        after,
    );
    assert_allocated_within_ms(
        v7_millis!(resolution.transitions[0].worktree_transition_id),
        before,
        after,
    );
}

// ---------------------------------------------------------------------------
// Continuity requires positive evidence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ancestry_from_another_repository_does_not_prove_continuity() {
    let mut harness = Harness::open().await;
    let repo_a = harness.path("repo-a");
    init_repo(&repo_a);
    let repo_a = canonical(&repo_a);
    harness.refresh(&repo_a).await;
    // B is a clone of A plus its own commit: a different filesystem identity
    // and a head that is unrelated to A's recorded heads.
    let repo_b = harness.path("repo-b");
    git(
        harness.temp.path(),
        &[
            "clone",
            "-q",
            &format!("file://{}", repo_a.display()),
            repo_b.to_str().unwrap(),
        ],
    );
    let repo_b = canonical(&repo_b);
    commit_file(&repo_b, "b.txt", "b");
    harness.refresh(&repo_b).await;
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 2);
    let instance_a = view
        .repositories
        .values()
        .find(|repository| repository.current_path == repo_a.to_string_lossy().as_ref())
        .unwrap()
        .clone();
    let b_head = head_oid(&repo_b);

    // Synthetic evidence at A's path whose only ancestry claim comes from
    // B's head: not A's head, no ref overlap with A, no A ancestor.
    let occurred = harness.tick();
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let mut evidence = probe_repository(
        &repo_a,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    evidence.head_oid = Some(b_head.clone());
    evidence.ref_tips = vec![("refs/heads/main".into(), b_head.clone())];
    evidence.head_ancestors = vec![b_head];
    assert!(evidence.omissions.is_empty());

    let resolution = resolve_repository(&RepositoryResolveInput {
        view: &view,
        evidence: &evidence,
        derived_from_hint: None,
    })
    .unwrap();
    // Ancestors of another repository instance never prove continuity with
    // A: the probe is complete and non-positive, so a new instance is
    // recorded instead of reusing A.
    assert_eq!(resolution.kind, Some(ResolutionKind::Create));
    let replacement = &resolution.repositories[0];
    assert_ne!(replacement.repository_id, instance_a.repository_id);
    assert_eq!(replacement.derived_from, Some(instance_a.repository_id));
}

// ---------------------------------------------------------------------------
// Continuity probe object presence: foreign, negative and damaged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn foreign_known_head_is_a_not_applicable_negative_without_omission() {
    let mut harness = Harness::open().await;
    // A's history must be genuinely foreign to B: the shared init fixture
    // would otherwise produce an identical first-commit OID in both object
    // stores. A gets its own distinct root commit.
    let repo_a = harness.path("repo-a");
    std::fs::create_dir_all(&repo_a).unwrap();
    git(&repo_a, &["init", "-q", "-b", "main"]);
    commit_file(&repo_a, "only-a.txt", "only-a");
    let repo_a = canonical(&repo_a);
    harness.refresh(&repo_a).await;
    let repo_b = harness.path("repo-b");
    init_repo(&repo_b);
    commit_file(&repo_b, "b.txt", "b");
    let repo_b = canonical(&repo_b);
    harness.refresh(&repo_b).await;
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 2);

    // Probing B with a view that also records A's head: A's head is not an
    // object in B at all. `cat-file --batch-check` reports `missing` — a
    // deterministic not-applicable negative, no omission and no merge-base —
    // while B's own head still proves its ancestry.
    let occurred = harness.tick();
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    assert_eq!(known_heads.len(), 2);
    let evidence = probe_repository(
        &repo_b,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    assert!(evidence.omissions.is_empty());
    assert_eq!(evidence.head_ancestors, vec![head_oid(&repo_b)]);

    // A routine refresh of B stays a stable no-delta: the foreign head never
    // turns into an ambiguity.
    let refresh = harness.refresh(&repo_b).await;
    assert_eq!(refresh.resolution.kind, Some(ResolutionKind::NoDelta));
    assert!(refresh.command.is_none());
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 2);
}

#[tokio::test]
async fn existing_non_ancestor_known_head_is_legitimate_negative_without_omission() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    let main_tip = head_oid(&repo);
    harness.refresh(&repo).await;
    // A sibling branch tip that exists in this object store but is not an
    // ancestor of main's HEAD.
    git(&repo, &["checkout", "-q", "-b", "sibling"]);
    commit_file(&repo, "b.txt", "b");
    harness.refresh(&repo).await;
    git(&repo, &["checkout", "-q", "main"]);
    assert_eq!(head_oid(&repo), main_tip);

    let view = harness.view().await;
    let occurred = harness.tick();
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    // The sibling tip exists (batch-check: commit) but merge-base exits 1:
    // a legitimate negative — no omission, and it is not collected.
    assert!(evidence.omissions.is_empty());
    assert_eq!(evidence.head_ancestors, vec![main_tip]);

    // Resolving stays on the established instance: a legal successor
    // snapshot for the head change, never a new repository.
    let refresh = harness.refresh(&repo).await;
    assert_eq!(refresh.resolution.kind, Some(ResolutionKind::Successor));
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 1);
}

#[tokio::test]
async fn damaged_object_store_yields_omission_and_never_a_new_instance() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    harness.refresh(&repo).await;
    commit_file(&repo, "b.txt", "b");
    let head = head_oid(&repo);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 1);

    // Damage the object store: HEAD's commit object is deleted while the ref
    // still resolves, so the parent's presence check passes but merge-base
    // can no longer run deterministically.
    let head_text = head.as_str();
    let object = repo
        .join(".git/objects")
        .join(&head_text[..2])
        .join(&head_text[2..]);
    assert!(object.exists());
    std::fs::remove_file(&object).unwrap();

    let occurred = harness.tick();
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    // Presence passes for the parent; merge-base then exits non-0/1, which
    // is a ContinuityAncestry omission — never a negative.
    assert!(evidence.omissions.iter().any(|omission| {
        omission.field == ProbeField::ContinuityAncestry
            && omission.reason == ProbeUnavailableReason::CorruptAdminMetadata
    }));

    // The resolver fails closed: ambiguous, zero objects, and the view keeps
    // exactly the one established instance.
    let refresh = harness.refresh(&repo).await;
    assert_eq!(refresh.resolution.kind, Some(ResolutionKind::Ambiguous));
    assert_eq!(
        refresh.resolution.detail.as_deref(),
        Some("continuity_evidence_incomplete")
    );
    assert!(refresh.resolution.repositories.is_empty());
    assert!(refresh.resolution.worktrees.is_empty());
    assert!(refresh.resolution.snapshots.is_empty());
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 1);
}

#[tokio::test]
async fn same_filesystem_identity_without_continuity_evidence_creates_new_instance() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let established = only_repository(&view).clone();

    // Synthetic probe of the very same admin directory (identical device /
    // inode and path, same object format) but a completely unrelated history:
    // no recorded HEAD, no proven ancestor, no ref overlap, no host evidence.
    let occurred = harness.tick();
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let mut evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    let foreign = GitOid::parse(&"f".repeat(40)).unwrap();
    evidence.head_oid = Some(foreign.clone());
    evidence.ref_tips = vec![("refs/heads/main".into(), foreign)];
    evidence.head_ancestors = Vec::new();
    assert!(evidence.omissions.is_empty());

    let resolve = |evidence: &GitProbeEvidence| {
        resolve_repository(&RepositoryResolveInput {
            view: &view,
            evidence,
            derived_from_hint: None,
        })
        .unwrap()
    };

    // Complete probe, no positive continuity evidence: never reuse the old
    // instance; record a new one linked by derived_from.
    let resolution = resolve(&evidence);
    assert_eq!(resolution.kind, Some(ResolutionKind::Create));
    let replacement = &resolution.repositories[0];
    assert_ne!(replacement.repository_id, established.repository_id);
    assert_eq!(replacement.derived_from, Some(established.repository_id));

    // The same evidence with an incomplete continuity probe fails closed.
    let clean = evidence.clone();
    evidence.omissions.push(ProbeOmission {
        field: ProbeField::RefTips,
        reason: ProbeUnavailableReason::OutputLimitExceeded,
    });
    let ambiguous = resolve(&evidence);
    assert_eq!(ambiguous.kind, Some(ResolutionKind::Ambiguous));
    assert_eq!(
        ambiguous.detail.as_deref(),
        Some("continuity_evidence_incomplete")
    );
    assert!(ambiguous.repositories.is_empty());
    assert!(ambiguous.worktrees.is_empty());
    assert!(ambiguous.snapshots.is_empty());
    assert!(ambiguous.transitions.is_empty());
    assert!(ambiguous.integrations.is_empty());

    // Commit the replacement through the writer for real; the projection
    // then carries two instances sharing one filesystem identity.
    let command = resolution
        .journal_command(occurred, CONFIG_HASH, ALGO)
        .unwrap()
        .unwrap();
    harness
        .writer
        .commit_if_frontier(&command, occurred, view.frontier)
        .await
        .unwrap();
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 2);
    let replacement_id = resolution.repositories[0].repository_id;
    assert_eq!(
        view.repositories[&replacement_id].derived_from,
        Some(established.repository_id)
    );
    // The old instance and its lineage stay in the view untouched.
    assert_eq!(
        view.repositories[&established.repository_id].derived_from,
        established.derived_from
    );

    // Resolving the same synthetic evidence against the two-candidate view
    // uniquely selects the replacement (its snapshot carries the foreign
    // head) and is a stable no-delta, not a permanent ambiguity.
    let again = resolve_repository(&RepositoryResolveInput {
        view: &view,
        evidence: &clean,
        derived_from_hint: None,
    })
    .unwrap();
    assert_eq!(again.kind, Some(ResolutionKind::NoDelta));
    assert!(again.repositories.is_empty());
    assert!(again.worktrees.is_empty());
    assert!(again.snapshots.is_empty());
    assert!(again.transitions.is_empty());
    assert!(
        again
            .journal_command(harness.tick(), CONFIG_HASH, ALGO)
            .unwrap()
            .is_none()
    );

    // Evidence whose head hits only the old instance's recorded head
    // uniquely selects the old instance instead (state unchanged there).
    let occurred = harness.tick();
    let view = harness.view().await;
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let real_evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    let select_old = resolve_repository(&RepositoryResolveInput {
        view: &view,
        evidence: &real_evidence,
        derived_from_hint: None,
    })
    .unwrap();
    assert_eq!(select_old.kind, Some(ResolutionKind::NoDelta));
    assert!(select_old.repositories.is_empty());
    assert!(select_old.transitions.is_empty());
    assert_eq!(view.repositories.len(), 2);

    // After a restart (writer reopened, projection rebuilt from the journal)
    // the same resolve against the rebuilt view yields the same outcome.
    let store_root = harness.temp.path().join("store");
    harness.writer = {
        let _reopen_gate = enter_reopen();
        drop(harness.writer);
        JournalWriter::open(&store_root).await.unwrap()
    };
    let view = harness.view().await;
    assert_eq!(view.repositories.len(), 2);
    assert!(view.repositories.contains_key(&established.repository_id));
    assert!(view.repositories.contains_key(&replacement_id));
    let after_restart = resolve_repository(&RepositoryResolveInput {
        view: &view,
        evidence: &clean,
        derived_from_hint: None,
    })
    .unwrap();
    assert_eq!(after_restart.kind, Some(ResolutionKind::NoDelta));
    assert!(after_restart.repositories.is_empty());
    assert!(after_restart.worktrees.is_empty());
    assert!(after_restart.snapshots.is_empty());
    assert!(after_restart.transitions.is_empty());
    assert!(after_restart.integrations.is_empty());
}

// ---------------------------------------------------------------------------
// Remote fingerprints never persist locator text
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remote_fingerprints_are_hashed_and_never_persist_locator_text() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://user:secret@example.com/org/repo.git",
        ],
    );

    // A password-bearing remote fails closed: omission recorded, no
    // fingerprint materializes.
    let occurred = harness.tick();
    let view = harness.view().await;
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    assert!(evidence.remote_fingerprints.is_empty());
    assert!(
        evidence
            .omissions
            .iter()
            .any(|omission| omission.field == ProbeField::RemoteFingerprints)
    );
    harness.refresh(&repo).await;
    let view = harness.view().await;
    assert!(only_repository(&view).remote_fingerprints.is_empty());

    // A clean remote yields a fingerprint in the closed hashed format.
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "https://example.com/org/repo.git",
        ],
    );
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let repository = only_repository(&view);
    assert_eq!(repository.remote_fingerprints.len(), 1);
    let fingerprint = &repository.remote_fingerprints[0];
    assert!(fingerprint.starts_with(REMOTE_FINGERPRINT_PREFIX));
    let hex_digits = &fingerprint[REMOTE_FINGERPRINT_PREFIX.len()..];
    assert_eq!(hex_digits.len(), 64);
    assert!(
        hex_digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        fingerprint,
        &remote_fingerprint("https://example.com/org/repo.git").unwrap()
    );
    let fingerprint = fingerprint.clone();

    // A non-default port is part of the remote identity and changes the
    // fingerprint; an explicit default port collapses to the same one.
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "https://example.com:8443/org/repo.git",
        ],
    );
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let ported = only_repository(&view).remote_fingerprints[0].clone();
    assert_ne!(ported, fingerprint);
    assert_eq!(
        ported,
        remote_fingerprint("https://example.com:8443/org/repo.git").unwrap()
    );
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "https://example.com:443/org/repo.git",
        ],
    );
    harness.refresh(&repo).await;
    let view = harness.view().await;
    assert_eq!(
        only_repository(&view).remote_fingerprints,
        vec![fingerprint]
    );

    // Leak proof: no persisted object payload contains the locator text.
    for row in harness.writer.object_rows().await.unwrap() {
        let payload = row.payload_json.as_deref().unwrap_or_default();
        assert!(
            !payload.contains("example.com"),
            "locator persisted: {payload}"
        );
        assert!(
            !payload.contains("user:secret"),
            "secret persisted: {payload}"
        );
        assert!(
            !payload.contains("https://example.com/org/repo.git"),
            "raw URL persisted: {payload}"
        );
    }
}

// ---------------------------------------------------------------------------
// Transition corrections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn corrections_create_successor_revisions_and_conflicts_fail_closed() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let linked = canonical(&harness.path("linked"));
    commit_file(&linked, "feature.txt", "feature");
    harness.refresh(&repo).await;
    harness.refresh(&linked).await;
    git(
        &repo,
        &["merge", "-q", "--no-ff", "-m", "merge feature", "feature"],
    );
    harness.refresh(&repo).await;

    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let source = worktree_at(&view, &linked).unwrap().clone();
    let destination = main_worktree(&view, repository_id).clone();
    let feature_head = head_oid(&linked);
    let main_head = head_oid(&repo);
    let ancestry = probe_is_ancestor(&repo, &feature_head, &main_head, &ProbeLimits::default());
    let integration = harness
        .commit_integration(IntegrationEvidence {
            source_worktree_instance_id: source.worktree_instance_id,
            destination_worktree_instance_id: destination.worktree_instance_id,
            source_snapshot_id: source.current_snapshot_id.unwrap(),
            destination_snapshot_id: destination.current_snapshot_id.unwrap(),
            kind: IntegrationKind::MergeCommit,
            ancestry: Some(ancestry.unwrap()),
            ancestry_evidence_ref: Some("ancestry-probe-1".into()),
            host_event_ref: Some("host-merge-event-1".into()),
            patch_equivalence_refs: Vec::new(),
            conflict_resolution_detected: false,
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec!["integration-evidence-1".into()],
            occurred_at_us: 0,
        })
        .await;
    let transition = &integration.transitions[0];
    let transition_id = transition.worktree_transition_id;
    assert_eq!(transition.transition_revision, 1);
    assert_eq!(
        integration.integrations[0].assessment,
        LineageAssessment::Proven
    );

    // Late evidence corrects the assessment through a successor revision.
    let occurred = harness.tick();
    let view = harness.view().await;
    let correction = correct_transition(
        &view,
        transition_id,
        LineageAssessment::Contradicted,
        "late-conflict-evidence",
        &["late-evidence-1".into()],
        occurred,
    )
    .unwrap();
    let command = correction
        .journal_command(occurred, CONFIG_HASH, ALGO)
        .unwrap()
        .unwrap();
    harness
        .writer
        .commit_if_frontier(&command, occurred, view.frontier)
        .await
        .unwrap();
    harness.writer.project().await.unwrap();

    let journal = harness.writer.journal_rows().await.unwrap();
    let revisions = journal
        .iter()
        .filter_map(|row| match row.payload().unwrap() {
            JournalPayload::WorktreeTransitionRecorded(value)
                if value.worktree_transition_id == transition_id =>
            {
                Some(value.transition_revision)
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(revisions, BTreeSet::from([1, 2]));

    let rows = harness.writer.object_rows().await.unwrap();
    let transition_rows = rows
        .iter()
        .filter(|row| row.row_id == format!("object:work:worktree_transition:{transition_id}"))
        .collect::<Vec<_>>();
    assert_eq!(transition_rows.len(), 1);
    assert_eq!(
        transition_rows[0].current_revision_id.as_deref(),
        Some(format!("{transition_id}@2").as_str())
    );
    let view = harness.view().await;
    let corrected = view.transitions.get(&transition_id).unwrap();
    assert_eq!(corrected.transition_revision, 2);
    assert_eq!(corrected.predecessor_revision, Some(1));
    assert_eq!(
        corrected.lineage_assessment,
        LineageAssessment::Contradicted
    );
    assert_eq!(
        corrected.correction_reason.as_deref(),
        Some("late-conflict-evidence")
    );

    // A hand-crafted same-revision different-content payload is rejected.
    let mut forged = corrected.clone();
    forged.lineage_assessment = LineageAssessment::Proven;
    forged.validate().unwrap();
    let occurred = harness.tick();
    let forged_command = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            occurred,
            CONFIG_HASH,
            ALGO,
            JournalPayload::WorktreeTransitionRecorded(Box::new(forged)),
        )],
    )
    .unwrap();
    assert!(
        harness
            .writer
            .commit(&forged_command, occurred)
            .await
            .is_err()
    );
    let view = harness.view().await;
    assert_eq!(
        view.transitions
            .get(&transition_id)
            .unwrap()
            .lineage_assessment,
        LineageAssessment::Contradicted
    );
}

// ---------------------------------------------------------------------------
// Integration events
// ---------------------------------------------------------------------------

struct IntegrationFixture {
    main: WorktreeInstance,
    feature: WorktreeInstance,
}

fn integration_fixture(view: &RepositoryCurrentView, feature_path: &Path) -> IntegrationFixture {
    let repository_id = only_repository(view).repository_id;
    IntegrationFixture {
        main: main_worktree(view, repository_id).clone(),
        feature: worktree_at(view, feature_path).unwrap().clone(),
    }
}

fn integration_evidence(
    fixture: &IntegrationFixture,
    kind: IntegrationKind,
    occurred: i64,
) -> IntegrationEvidence {
    IntegrationEvidence {
        source_worktree_instance_id: fixture.feature.worktree_instance_id,
        destination_worktree_instance_id: fixture.main.worktree_instance_id,
        source_snapshot_id: fixture.feature.current_snapshot_id.unwrap(),
        destination_snapshot_id: fixture.main.current_snapshot_id.unwrap(),
        kind,
        ancestry: None,
        ancestry_evidence_ref: None,
        host_event_ref: None,
        patch_equivalence_refs: Vec::new(),
        conflict_resolution_detected: false,
        revalidated_anchor_refs: Vec::new(),
        evidence_refs: vec![format!("integration-evidence-{occurred}")],
        occurred_at_us: occurred,
    }
}

#[tokio::test]
async fn integration_kinds_follow_their_evidence_rules() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("feature").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let feature = canonical(&harness.path("feature"));
    let feature_head = commit_file(&feature, "feature.txt", "feature");
    harness.refresh(&repo).await;
    harness.refresh(&feature).await;

    // fast_forward: ancestry + host event + matching heads prove lineage.
    git(&repo, &["merge", "-q", "--ff-only", "feature"]);
    harness.refresh(&repo).await;
    let fixture = integration_fixture(&harness.view().await, &feature);
    let mut evidence = integration_evidence(&fixture, IntegrationKind::FastForward, 0);
    evidence.ancestry = Some(
        probe_is_ancestor(
            &repo,
            &GitOid::parse(&feature_head).unwrap(),
            &head_oid(&repo),
            &ProbeLimits::default(),
        )
        .unwrap(),
    );
    evidence.ancestry_evidence_ref = Some("ancestry-ff".into());
    evidence.host_event_ref = Some("host-ff".into());
    let resolution = harness.commit_integration(evidence).await;
    assert_eq!(
        resolution.integrations[0].assessment,
        LineageAssessment::Proven
    );
    assert_eq!(
        resolution.transitions[0].kind,
        TransitionKind::MergeIntegrated
    );

    // ancestry = false contradicts an ancestry-based claim.
    let fixture = integration_fixture(&harness.view().await, &feature);
    let mut evidence = integration_evidence(&fixture, IntegrationKind::FastForward, 1);
    evidence.ancestry = Some(false);
    evidence.ancestry_evidence_ref = Some("ancestry-ff-2".into());
    evidence.host_event_ref = Some("host-ff-2".into());
    let resolution = harness.commit_integration(evidence).await;
    assert_eq!(
        resolution.integrations[0].assessment,
        LineageAssessment::Contradicted
    );

    // merge_commit: divergent heads joined by a real merge.
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("feature2").to_str().unwrap(),
            "-b",
            "feature2",
        ],
    );
    let feature2 = canonical(&harness.path("feature2"));
    let side_head = commit_file(&feature2, "side.txt", "side");
    commit_file(&repo, "main.txt", "main");
    git(
        &repo,
        &["merge", "-q", "--no-ff", "-m", "merge feature2", "feature2"],
    );
    harness.refresh(&feature2).await;
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let main = main_worktree(&view, repository_id).clone();
    let side = worktree_at(&view, &feature2).unwrap().clone();
    let resolution = harness
        .commit_integration(IntegrationEvidence {
            source_worktree_instance_id: side.worktree_instance_id,
            destination_worktree_instance_id: main.worktree_instance_id,
            source_snapshot_id: side.current_snapshot_id.unwrap(),
            destination_snapshot_id: main.current_snapshot_id.unwrap(),
            kind: IntegrationKind::MergeCommit,
            ancestry: Some(
                probe_is_ancestor(
                    &repo,
                    &GitOid::parse(&side_head).unwrap(),
                    &head_oid(&repo),
                    &ProbeLimits::default(),
                )
                .unwrap(),
            ),
            ancestry_evidence_ref: Some("ancestry-merge".into()),
            host_event_ref: Some("host-merge".into()),
            patch_equivalence_refs: Vec::new(),
            conflict_resolution_detected: false,
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec!["integration-merge".into()],
            occurred_at_us: 2,
        })
        .await;
    assert_eq!(
        resolution.integrations[0].assessment,
        LineageAssessment::Proven
    );

    // branch merged does not terminate the source worktree.
    let view = harness.view().await;
    assert_eq!(
        view.worktrees
            .get(&side.worktree_instance_id)
            .unwrap()
            .lifecycle,
        WorktreeLifecycle::Active
    );

    // cherry_pick: patch equivalence proves the transfer.
    let picked = commit_file(&feature2, "picked.txt", "picked");
    let picked_base = git(&feature2, &["rev-parse", "HEAD~1"]);
    let main_before_pick = head_oid(&repo);
    git(&repo, &["cherry-pick", &picked]);
    let pick_head = head_oid(&repo);
    harness.refresh(&feature2).await;
    harness.refresh(&repo).await;
    let patch = probe_patch_equivalence(
        &repo,
        &GitOid::parse(&picked_base).unwrap(),
        &GitOid::parse(&picked).unwrap(),
        &main_before_pick,
        &pick_head,
        &ProbeLimits::default(),
    )
    .unwrap()
    .expect("identical diffs must yield a patch equivalence ref");
    assert!(patch.starts_with("patch:"));
    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let main = main_worktree(&view, repository_id).clone();
    let side = worktree_at(&view, &feature2).unwrap().clone();
    let mut evidence = IntegrationEvidence {
        source_worktree_instance_id: side.worktree_instance_id,
        destination_worktree_instance_id: main.worktree_instance_id,
        source_snapshot_id: side.current_snapshot_id.unwrap(),
        destination_snapshot_id: main.current_snapshot_id.unwrap(),
        kind: IntegrationKind::CherryPick,
        ancestry: None,
        ancestry_evidence_ref: None,
        host_event_ref: Some("host-cherry-pick".into()),
        patch_equivalence_refs: vec![patch.clone()],
        conflict_resolution_detected: false,
        revalidated_anchor_refs: Vec::new(),
        evidence_refs: vec!["integration-cherry-pick".into()],
        occurred_at_us: 3,
    };
    let resolution = harness.commit_integration(evidence.clone_for_test()).await;
    assert_eq!(
        resolution.integrations[0].assessment,
        LineageAssessment::Proven
    );
    assert_eq!(
        resolution.transitions[0].kind,
        TransitionKind::PatchTransferred
    );

    // Conflict resolution without revalidated anchors caps at partial.
    evidence.conflict_resolution_detected = true;
    evidence.occurred_at_us = 4;
    evidence.evidence_refs = vec!["integration-cherry-pick-conflict".into()];
    let resolution = harness.commit_integration(evidence.clone_for_test()).await;
    assert_eq!(
        resolution.integrations[0].assessment,
        LineageAssessment::Partial
    );

    // Patch-based kinds without patch evidence are rejected.
    evidence.conflict_resolution_detected = false;
    evidence.patch_equivalence_refs = Vec::new();
    evidence.occurred_at_us = 5;
    let view = harness.view().await;
    assert_eq!(
        resolve_integration(&view, &evidence),
        Err(RepositoryResolveError::InsufficientEvidence)
    );

    // Cross-repository transfer can only ever be partial.
    git(
        harness.temp.path(),
        &[
            "clone",
            "-q",
            &format!("file://{}", repo.display()),
            harness.path("clone").to_str().unwrap(),
        ],
    );
    let cloned = canonical(&harness.path("clone"));
    harness.refresh(&cloned).await;
    let view = harness.view().await;
    let source_repo = view
        .repositories
        .values()
        .find(|repository| repository.current_path == repo.to_string_lossy().as_ref())
        .unwrap();
    let clone_repo = view
        .repositories
        .values()
        .find(|repository| repository.current_path == cloned.to_string_lossy().as_ref())
        .unwrap();
    let source = main_worktree(&view, source_repo.repository_id).clone();
    let destination = main_worktree(&view, clone_repo.repository_id).clone();
    let resolution = harness
        .commit_integration(IntegrationEvidence {
            source_worktree_instance_id: source.worktree_instance_id,
            destination_worktree_instance_id: destination.worktree_instance_id,
            source_snapshot_id: source.current_snapshot_id.unwrap(),
            destination_snapshot_id: destination.current_snapshot_id.unwrap(),
            kind: IntegrationKind::CherryPick,
            ancestry: None,
            ancestry_evidence_ref: None,
            host_event_ref: Some("host-cross-repo".into()),
            patch_equivalence_refs: vec![patch],
            conflict_resolution_detected: false,
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec!["integration-cross-repo".into()],
            occurred_at_us: 6,
        })
        .await;
    assert_eq!(
        resolution.integrations[0].assessment,
        LineageAssessment::Partial
    );
    assert_eq!(
        resolution.integrations[0].repository_instance_id,
        clone_repo.repository_id
    );
}

// `IntegrationEvidence` is not `Clone`; tests rebuild it field by field.
trait CloneForTest {
    fn clone_for_test(&self) -> Self;
}

impl CloneForTest for IntegrationEvidence {
    fn clone_for_test(&self) -> Self {
        Self {
            source_worktree_instance_id: self.source_worktree_instance_id,
            destination_worktree_instance_id: self.destination_worktree_instance_id,
            source_snapshot_id: self.source_snapshot_id,
            destination_snapshot_id: self.destination_snapshot_id,
            kind: self.kind,
            ancestry: self.ancestry,
            ancestry_evidence_ref: self.ancestry_evidence_ref.clone(),
            host_event_ref: self.host_event_ref.clone(),
            patch_equivalence_refs: self.patch_equivalence_refs.clone(),
            conflict_resolution_detected: self.conflict_resolution_detected,
            revalidated_anchor_refs: self.revalidated_anchor_refs.clone(),
            evidence_refs: self.evidence_refs.clone(),
            occurred_at_us: self.occurred_at_us,
        }
    }
}

// ---------------------------------------------------------------------------
// Physical identity stays independent from worktree scope
// ---------------------------------------------------------------------------

fn exact_correlation(source: &str, ordinal: u32) -> HostCorrelationEvidence {
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: Some("host-a".into()),
        host_trace_lineage_id: Some("trace-a".into()),
        host_lane_key: Some("lane-a".into()),
        canonical_event_family: Some(CanonicalEventFamily::Mutate),
        native_request_id: Some("request-a".into()),
        physical_execution_ordinal: Some(ordinal),
        pairing_role: ObservationRole::Result,
        field_provenance: fields
            .into_iter()
            .map(|field| CorrelationFieldClaim {
                field,
                source_ref: source.into(),
                evidence_ref: format!("canary-{source}"),
            })
            .collect(),
        adapter_manifest_ref: "adapter-manifest-a".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: Some("strong-gate-a".into()),
        admission: CorrelationAdmission::ExactCapable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn observation(
    record: &str,
    correlation: HostCorrelationEvidence,
    claims: Vec<ScopeEffectClaim>,
) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("source-{record}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record_identity = SourceRecordIdentity::parse(format!("record-{record}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record_identity).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record_identity).unwrap();
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: format!("source-ref-{record}"),
        source_session_ref: "session-a".into(),
        source_revision: revision.clone(),
        source_record_identity: record_identity.clone(),
        identity_strength: IdentityStrength::StableNative,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(1),
        observation_role: ObservationRole::Result,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: DIGEST.into(),
        protected_length: 1,
        original_length: 1,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        protection_key_generation: 1,
        event_time_us: 1,
        recorded_at_us: 1,
        lifecycle: None,
    };
    let fingerprint = payload_fingerprint(1, b"x", None).unwrap();
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: instance,
        source_revision: revision,
        source_record_identity: record_identity,
        observation_role: ObservationRole::Result,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: evertrace_domain::evidence::hex(&fingerprint),
        source_receipt_ref: receipt_id,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Complete,
        adapter_revision: 1,
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        correlation,
        scope_effect_claims: claims,
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn scope_claim(repository: RepositoryId, worktree: WorktreeId) -> ScopeEffectClaim {
    ScopeEffectClaim {
        effect_role: EffectRole::Mutate,
        repository_instance_id: Some(repository),
        worktree_instance_id: Some(worktree),
        pre_snapshot_id: Some(
            WorktreeSnapshotId::from_str("wts:01890f47-6a4a-7cc1-98b9-01890f476a31").unwrap(),
        ),
        post_snapshot_id: Some(
            WorktreeSnapshotId::from_str("wts:01890f47-6a4a-7cc1-98b9-01890f476a32").unwrap(),
        ),
        experiment_run_ids: Vec::new(),
        artifact_refs: Vec::new(),
        evidence_refs: Vec::new(),
    }
}

fn evidence_command(
    command_id: CommandId,
    receipt: SourceReceipt,
    observation: SourceObservation,
    occurred: i64,
) -> JournalCommand {
    let watermark = SourceIngestWatermark {
        source_instance_id: receipt.source_instance_id.clone(),
        source_revision: receipt.source_revision.clone(),
        source_sequence: receipt.source_sequence,
    };
    let target = observation.source_observation_id.to_string();
    let payloads = vec![
        JournalPayload::SourceReceiptRecorded(Box::new(receipt)),
        JournalPayload::SourceObservationRecorded(Box::new(observation)),
        JournalPayload::SourceIngestWatermark(watermark),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::EvidenceSurface,
            target_id: target.clone(),
            algorithm_revision: "physical-v1".into(),
            source_watermark: 1,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: target,
            algorithm_revision: "physical-v1".into(),
            source_watermark: 1,
        }),
    ];
    JournalCommand::new(
        command_id,
        payloads
            .into_iter()
            .map(|payload| {
                JournalEventDraft::runtime(occurred, CONFIG_HASH, "physical-v1", payload)
            })
            .collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn one_operation_can_span_worktrees_and_ordinals_never_merge() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    let linked = canonical(&harness.path("linked"));
    harness.refresh(&repo).await;
    let view = harness.view().await;
    let repository_id = only_repository(&view).repository_id;
    let main_id = main_worktree(&view, repository_id).worktree_instance_id;
    let linked_id = worktree_at(&view, &linked).unwrap().worktree_instance_id;

    // One exact occurrence touching two worktrees: one operation, two scope
    // effects.
    let (receipt, result) = observation(
        "s11-result",
        exact_correlation("s11", 1),
        vec![
            scope_claim(repository_id, main_id),
            scope_claim(repository_id, linked_id),
        ],
    );
    let occurred = harness.tick();
    harness
        .writer
        .commit(
            &evidence_command(CommandId::new_v7(), receipt, result.clone(), occurred),
            occurred,
        )
        .await
        .unwrap();
    harness.writer.project().await.unwrap();
    let normalizer = PhysicalNormalizer::new(1).unwrap();
    let normalized = normalizer
        .normalize(std::slice::from_ref(&result), None)
        .unwrap();
    assert_eq!(normalized.occurrences.len(), 1);
    assert_eq!(normalized.operations.len(), 1);
    assert_eq!(normalized.scope_effects.len(), 2);
    assert_eq!(
        normalized
            .scope_effects
            .iter()
            .map(|effect| effect.worktree_instance_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([Some(main_id), Some(linked_id)])
    );
    let occurred = harness.tick();
    harness
        .writer
        .commit(
            &normalized
                .journal_command(CommandId::new_v7(), occurred, CONFIG_HASH, "physical-v1")
                .unwrap(),
            occurred,
        )
        .await
        .unwrap();

    // The same command text executed with a different physical ordinal is a
    // different physical execution and never deduplicates.
    let (receipt_b, second) = observation(
        "s11-result-b",
        exact_correlation("s11", 2),
        vec![scope_claim(repository_id, linked_id)],
    );
    let occurred = harness.tick();
    harness
        .writer
        .commit(
            &evidence_command(CommandId::new_v7(), receipt_b, second.clone(), occurred),
            occurred,
        )
        .await
        .unwrap();
    harness.writer.project().await.unwrap();
    let pair = normalizer.normalize(&[result, second], None).unwrap();
    assert_eq!(pair.occurrences.len(), 2);
    assert_eq!(pair.operations.len(), 2);

    // Relation DTOs stay consistent on both families.
    let relations =
        build_physical_relation_rows(&pair.occurrences, &pair.operations, &pair.scope_effects)
            .unwrap();
    assert_eq!(
        relations
            .iter()
            .filter(|row| row.kind == PhysicalRelationKind::HostOccurrenceToOperation)
            .count(),
        2
    );
    let view = harness.view().await;
    let repository_relations = view.relation_rows().unwrap();
    assert_eq!(
        repository_relations
            .iter()
            .filter(|row| row.kind
                == evertrace_store::relations::RepositoryRelationKind::RepositoryToWorktree)
            .count(),
        2
    );
}

// ---------------------------------------------------------------------------
// Journal/store closure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replay_stale_frontier_no_delta_and_projection_are_closed() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    let first = harness.refresh(&repo).await;
    let command = first.command.clone().unwrap();

    // Lost-ack retry: re-submitting the identical already-constructed command
    // hits the writer's replay path and produces no duplicate object rows.
    let view_before = harness.view().await;
    let object_rows_before = harness.writer.object_rows().await.unwrap().len();
    let replay = harness
        .writer
        .commit_if_frontier(&command, 10_000, first.frontier + 1)
        .await
        .unwrap();
    assert!(replay.replayed);
    let view_after = harness.view().await;
    assert_eq!(view_after, view_before);
    assert_eq!(
        harness.writer.object_rows().await.unwrap().len(),
        object_rows_before
    );
    assert_eq!(view_after.repositories.len(), 1);
    assert_eq!(view_after.worktrees.len(), 1);
    assert_eq!(view_after.snapshots.len(), 1);

    // A stale frontier is rejected and leaves the journal untouched.
    commit_file(&repo, "b.txt", "b");
    let occurred = harness.tick();
    let view = harness.view().await;
    let refs = vec![format!("probe-evidence-{occurred}")];
    let known_heads = known_head_oids(&view);
    let evidence = probe_repository(
        &repo,
        HostTrustDecision::Trusted,
        &refs,
        occurred,
        &ProbeLimits::default(),
        &view.known_admin_paths(),
        &known_heads,
    )
    .unwrap();
    let resolution = resolve_repository(&RepositoryResolveInput {
        view: &view,
        evidence: &evidence,
        derived_from_hint: None,
    })
    .unwrap();
    let next = resolution
        .journal_command(occurred, CONFIG_HASH, ALGO)
        .unwrap()
        .unwrap();
    let rows_before = harness.writer.journal_rows().await.unwrap().len();
    assert_eq!(
        harness
            .writer
            .commit_if_frontier(&next, occurred, view.frontier + 100)
            .await,
        Err(StoreError::StaleFrontier)
    );
    assert_eq!(
        harness.writer.journal_rows().await.unwrap().len(),
        rows_before
    );
    harness
        .writer
        .commit_if_frontier(&next, occurred, view.frontier)
        .await
        .unwrap();

    // A no-change probe produces no command at all.
    let quiet = harness.refresh(&repo).await;
    assert_eq!(quiet.resolution.kind, Some(ResolutionKind::NoDelta));
    assert!(quiet.command.is_none());

    // Incremental projection equals full reduction.
    let incremental = harness.writer.project().await.unwrap();
    let full = reduce_journal(&harness.writer.journal_rows().await.unwrap()).unwrap();
    assert_eq!(incremental, full);
    assert_eq!(incremental, harness.writer.full_projection().await.unwrap());

    // An incomplete command closure (snapshot without its worktree) is
    // rejected at admission.
    let forged = evertrace_domain::repository::WorktreeSnapshot {
        worktree_snapshot_id: WorktreeSnapshotId::from_str(
            "wts:01890f47-6a4a-7cc1-98b9-01890f476a99",
        )
        .unwrap(),
        worktree_instance_id: WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a99")
            .unwrap(),
        head_oid: None,
        tree_oid: None,
        branch_ref: None,
        detached_head: false,
        tracked_diff_digest: None,
        index_digest: None,
        untracked_manifest_digest: None,
        relevant_anchor_digests: Vec::new(),
        dependency_fingerprints: Vec::new(),
        toolchain_fingerprint: None,
        git_operation: GitOperation::None,
        captured_at_us: 1,
        evidence_refs: vec!["forged".into()],
        capture_status: SnapshotCaptureStatus::Complete,
        omission_reasons: Vec::new(),
    };
    forged.validate().unwrap();
    let occurred = harness.tick();
    let forged_command = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            occurred,
            CONFIG_HASH,
            ALGO,
            JournalPayload::WorktreeSnapshotRecorded(Box::new(forged)),
        )],
    )
    .unwrap();
    assert!(
        harness
            .writer
            .commit(&forged_command, occurred)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn production_tables_stay_at_journal_and_objects() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    harness.refresh(&canonical(&repo)).await;
    assert_eq!(
        harness.writer.table_names().await.unwrap(),
        vec!["evertrace_journal", "evertrace_objects"]
    );

    // A reserved L0002 table makes opening the store fail closed.
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let reader = CompatibilityStore::connect_local(&root).await.unwrap();
    reader
        .connection()
        .create_empty_table("evertrace_relations", objects_schema())
        .execute()
        .await
        .unwrap();
    assert!(JournalWriter::open(&root).await.is_err());
}

#[tokio::test]
async fn ancestry_and_patch_probes_reflect_real_repository_topology() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    let base = init_repo(&repo);
    let repo = canonical(&repo);
    let tip = commit_file(&repo, "b.txt", "b");
    harness.refresh(&repo).await;

    let base_oid = GitOid::parse(&base).unwrap();
    let tip_oid = GitOid::parse(&tip).unwrap();
    let limits = ProbeLimits::default();
    assert!(probe_is_ancestor(&repo, &base_oid, &tip_oid, &limits).unwrap());
    assert!(!probe_is_ancestor(&repo, &tip_oid, &base_oid, &limits).unwrap());

    // Equal diffs are equivalent; different diffs are not.
    let equivalent =
        probe_patch_equivalence(&repo, &base_oid, &tip_oid, &base_oid, &tip_oid, &limits).unwrap();
    assert!(equivalent.is_some());
    let other = commit_file(&repo, "c.txt", "different content");
    let other_oid = GitOid::parse(&other).unwrap();
    assert_eq!(
        probe_patch_equivalence(&repo, &base_oid, &tip_oid, &tip_oid, &other_oid, &limits).unwrap(),
        None
    );

    // Probe entry points reject invalid input instead of guessing.
    assert_eq!(
        probe_is_ancestor(Path::new("relative"), &base_oid, &tip_oid, &limits),
        Err(evertrace_engine::repository::RepositoryProbeError::InvalidInput)
    );
    let mut zero = limits;
    zero.max_stdout_bytes = 0;
    assert_eq!(
        probe_is_ancestor(&repo, &base_oid, &tip_oid, &zero),
        Err(evertrace_engine::repository::RepositoryProbeError::InvalidInput)
    );
}

#[tokio::test]
async fn object_rows_only_use_s11_object_kinds_for_repository_data() {
    let mut harness = Harness::open().await;
    let repo = harness.path("repo");
    init_repo(&repo);
    let repo = canonical(&repo);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            harness.path("linked").to_str().unwrap(),
            "-b",
            "feature",
        ],
    );
    harness.refresh(&repo).await;
    commit_file(&repo, "b.txt", "b");
    harness.refresh(&repo).await;

    let known: BTreeSet<&str> = BTreeSet::from([
        "repository",
        "worktree",
        "worktree_snapshot",
        "worktree_transition",
        "integration_event",
    ]);
    let rows = harness.writer.object_rows().await.unwrap();
    let kinds = rows
        .iter()
        .filter_map(|row| row.object_kind.as_deref())
        .collect::<BTreeSet<_>>();
    assert!(!kinds.is_empty());
    assert!(kinds.is_subset(&known), "unexpected kinds: {kinds:?}");
    for forbidden in ["task", "attempt", "episode", "recovery_bundle"] {
        assert!(
            rows.iter().all(|row| {
                !row.row_id.contains(forbidden) && row.object_kind.as_deref() != Some(forbidden)
            }),
            "forbidden object kind {forbidden} materialized"
        );
    }

    // Row identity stays symmetric with the current view.
    let view = harness.view().await;
    for repository in view.repositories.values() {
        let row_id = format!("object:work:repository:{}", repository.repository_id);
        assert!(rows.iter().any(|row| row.row_id == row_id));
    }
    let reader = CompatibilityStore::connect_local(&harness.temp.path().join("store"))
        .await
        .unwrap();
    let objects = reader
        .connection()
        .open_table(OBJECTS_TABLE)
        .execute()
        .await
        .unwrap();
    assert!(objects.version().await.unwrap() > 0);
}
