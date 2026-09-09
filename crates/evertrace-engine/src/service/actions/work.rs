//! Explicit, source-backed organization; never an active Work binding.
use super::*;
use evertrace_domain::{
    ids::{TaskId, WorkstreamId},
    work::{
        PhaseContract, Task, TaskIdentityConfidence, TaskLifecycle, Workstream, WorkstreamStatus,
    },
};
use evertrace_store::WorkIdentityCurrentView;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Choice {
    Root,
    Continue,
    Switch,
    Fork,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    kind: String,
    choice: Choice,
    task_id: TaskId,
    expected_task_revision: Option<RevisionId>,
    from_task_id: Option<TaskId>,
    goal: String,
    workstream: Option<StreamDeclaration>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StreamDeclaration {
    workstream_id: WorkstreamId,
    expected_revision: Option<RevisionId>,
    parent_workstream_id: Option<WorkstreamId>,
    goal: Option<String>,
    target_family: Option<String>,
    hypothesis_or_failure_family: Option<String>,
    acceptance_boundary: Option<String>,
    phase_contract: Option<PhaseContract>,
}

impl Declaration {
    fn protect(&mut self, key: &evertrace_capture::DeviceKey) -> Result<(), McpServiceError> {
        let protect = |text: &mut String| -> Result<(), McpServiceError> {
            let value = evertrace_capture::protect(text.as_bytes(), key)
                .map_err(|_| McpServiceError::Store)?;
            *text = String::from_utf8(value.protected_bytes().to_vec())
                .map_err(|_| McpServiceError::Store)?;
            Ok(())
        };
        protect(&mut self.goal)?;
        if let Some(stream) = &mut self.workstream {
            for text in [
                &mut stream.goal,
                &mut stream.target_family,
                &mut stream.hypothesis_or_failure_family,
                &mut stream.acceptance_boundary,
            ]
            .into_iter()
            .flatten()
            {
                protect(text)?;
            }
            if let Some(phase) = &mut stream.phase_contract {
                for text in [
                    &mut phase.local_goal,
                    &mut phase.phase_label,
                    &mut phase.acceptance_boundary,
                    &mut phase.expected_state_transition,
                ] {
                    protect(text)?;
                }
                for text in phase
                    .primary_targets
                    .iter_mut()
                    .chain(&mut phase.entry_conditions)
                {
                    protect(text)?;
                }
            }
        }
        Ok(())
    }
}

pub(super) fn is_work_annotation(input: &str) -> bool {
    serde_json::from_str::<Value>(input)
        .ok()
        .and_then(|value| value.get("kind").cloned())
        == Some(Value::String("work_annotation".into()))
}

pub(super) fn has_work_refs(action: McpServiceAction, input: &str, refs: &[String]) -> bool {
    matches!(action, McpServiceAction::Search | McpServiceAction::Get)
        && (input.parse::<TaskId>().is_ok()
            || input.parse::<WorkstreamId>().is_ok()
            || refs.iter().any(|value| {
                value.parse::<TaskId>().is_ok() || value.parse::<WorkstreamId>().is_ok()
            }))
}

fn verified_session(binding: &McpResolvedScope) -> Option<&str> {
    matches!(binding.mechanism, McpScopeMechanism::ExactClaim)
        .then_some(binding.anchor.as_ref()?.session_id.as_str())
}

fn passive_result(
    request_id: RequestId,
    items: Vec<McpServiceItem>,
    warnings: Vec<String>,
) -> McpServiceResult {
    McpServiceResult {
        request_id,
        status: McpServiceStatus::Partial,
        scope: "explicit_work_evidence".into(),
        freshness: "current".into(),
        completeness: "partial".into(),
        items,
        warnings,
        truncated: false,
        next_refs: vec![],
    }
}

fn invalid(request_id: RequestId, reason: &'static str) -> McpServiceResult {
    empty_result(
        request_id,
        McpServiceStatus::InvalidInput,
        "explicit_work_evidence",
        "unknown",
        [reason],
    )
}

fn source_pair(
    snapshot: &ProjectionSnapshot,
    reference: &str,
) -> Result<
    Option<(
        evertrace_domain::evidence::SourceReceipt,
        evertrace_domain::evidence::SourceObservation,
    )>,
    McpServiceError,
> {
    let Some((row, true)) = select_object_row(snapshot, reference).ok().flatten() else {
        return Ok(None);
    };
    let payload = serde_json::from_str::<JournalPayload>(
        row.payload_json.as_deref().ok_or(McpServiceError::Store)?,
    )
    .map_err(|_| McpServiceError::Store)?;
    let observation_id = match payload {
        JournalPayload::SourceReceiptRecorded(value) => value.source_observation_id,
        JournalPayload::SourceObservationRecorded(value) => value.source_observation_id,
        _ => return Ok(None),
    };
    let Some(observation_row) = snapshot.row(&format!(
        "object:evidence:source_observation:{observation_id}"
    )) else {
        return Ok(None);
    };
    let JournalPayload::SourceObservationRecorded(observation) = serde_json::from_str(
        observation_row
            .payload_json
            .as_deref()
            .ok_or(McpServiceError::Store)?,
    )
    .map_err(|_| McpServiceError::Store)?
    else {
        return Err(McpServiceError::Store);
    };
    let Some(receipt_row) = snapshot.row(&format!(
        "object:evidence:source_receipt:{}",
        observation.source_receipt_ref
    )) else {
        return Ok(None);
    };
    let JournalPayload::SourceReceiptRecorded(receipt) = serde_json::from_str(
        receipt_row
            .payload_json
            .as_deref()
            .ok_or(McpServiceError::Store)?,
    )
    .map_err(|_| McpServiceError::Store)?
    else {
        return Err(McpServiceError::Store);
    };
    if receipt.source_observation_id != observation_id {
        return Ok(None);
    }
    if read::retained_forgotten_source(snapshot, observation_row)? {
        return Ok(None);
    }
    Ok(Some((*receipt, *observation)))
}

fn submitted(
    receipt: &evertrace_domain::evidence::SourceReceipt,
    observation: &evertrace_domain::evidence::SourceObservation,
    session: &str,
) -> bool {
    receipt.source_session_ref == session
        && receipt.source_kind == EvidenceSourceKind::CodexHook
        && receipt.observation_role == ObservationRole::Message
        && observation.observation_role == ObservationRole::Message
        && observation.source_role == SourceRole::Host
        && observation.content_trust == ContentTrust::Observed
        && receipt.capture_completeness == CaptureCompleteness::Partial
        && observation.capture_completeness == CaptureCompleteness::Partial
}

fn repository_visible(
    snapshot: &ProjectionSnapshot,
    binding: &McpResolvedScope,
    repository: evertrace_domain::ids::RepositoryId,
    worktrees: &[evertrace_domain::ids::WorktreeId],
    budget: &mut Duration,
) -> Result<bool, McpServiceError> {
    if evertrace_store::ScopePurgeCurrentView::from_snapshot(snapshot)
        .map_err(|_| McpServiceError::Store)?
        .events
        .contains_key(&repository)
    {
        return Ok(false);
    }
    let Some(report) = binding.repository_report.as_deref() else {
        return Ok(false);
    };
    let current = evertrace_store::repository::RepositoryCurrentView::from_snapshot(snapshot)
        .map_err(|_| McpServiceError::Store)?;
    // A repository-only target may use its exact current root worktree, not
    // a caller cwd or an arbitrary sibling checkout.
    let root_worktree;
    let worktrees = if worktrees.is_empty() {
        let Some(repo) = current.repositories.get(&repository) else {
            return Ok(false);
        };
        let mut roots = current.worktrees.values().filter(|value| {
            value.repository_instance_id == repository
                && value.current_path.as_deref() == Some(repo.current_path.as_str())
        });
        let Some(root) = roots.next() else {
            return Ok(false);
        };
        if roots.next().is_some() {
            return Ok(false);
        }
        root_worktree = [root.worktree_instance_id];
        &root_worktree
    } else {
        worktrees
    };
    for id in worktrees {
        if current
            .worktrees
            .get(id)
            .is_none_or(|worktree| worktree.repository_instance_id != repository)
        {
            return Ok(false);
        }
        let start = Instant::now();
        let result = crate::repository::read_report_repository_trust_before(
            report,
            &current,
            *id,
            start + *budget,
        );
        *budget = budget.saturating_sub(start.elapsed());
        if result.state != evertrace_codex::policy::RepositoryTrustState::Trusted {
            return Ok(false);
        }
    }
    Ok(true)
}

fn work_visible(
    snapshot: &ProjectionSnapshot,
    binding: &McpResolvedScope,
    task: &Task,
    budget: &mut Duration,
) -> Result<bool, McpServiceError> {
    for membership in &task.scope_memberships {
        if let Some(repository) = membership.repository_instance_id
            && !repository_visible(
                snapshot,
                binding,
                repository,
                &membership.worktree_instance_ids,
                budget,
            )?
        {
            return Ok(false);
        }
    }
    for reference in &task.request_root_refs {
        let Some((receipt, _)) = source_pair(snapshot, reference)? else {
            return Ok(false);
        };
        if let Some(repository) = receipt.repository_instance_id
            && !repository_visible(
                snapshot,
                binding,
                repository,
                receipt.worktree_instance_id.as_slice(),
                budget,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn missing_stream_fields(value: Option<&StreamDeclaration>) -> Vec<String> {
    let Some(value) = value else {
        return vec!["missing_workstream_declaration".into()];
    };
    [
        ("workstream_goal", value.goal.is_some()),
        ("target_family", value.target_family.is_some()),
        (
            "hypothesis_or_failure_family",
            value.hypothesis_or_failure_family.is_some(),
        ),
        ("acceptance_boundary", value.acceptance_boundary.is_some()),
        ("phase_contract", value.phase_contract.is_some()),
    ]
    .into_iter()
    .filter(|(_, present)| !present)
    .map(|(name, _)| format!("missing_{name}"))
    .collect()
}

fn stream_matches(stream: &Workstream, value: &StreamDeclaration, task: &Task) -> bool {
    stream.task_id == task.task_id
        && stream.root_goal == task.canonical_goal
        && !stream.status.is_terminal()
        && stream.parent_workstream_id == value.parent_workstream_id
        && Some(stream.workstream_goal.as_str()) == value.goal.as_deref()
        && Some(stream.target_family.as_str()) == value.target_family.as_deref()
        && Some(stream.hypothesis_or_failure_family.as_str())
            == value.hypothesis_or_failure_family.as_deref()
        && Some(stream.acceptance_boundary.as_str()) == value.acceptance_boundary.as_deref()
        && Some(&stream.phase_contract) == value.phase_contract.as_ref()
}

fn build_stream(
    value: &StreamDeclaration,
    task: &Task,
    previous: Option<&Workstream>,
    watermark: u64,
) -> Workstream {
    Workstream {
        workstream_id: value.workstream_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: previous.map(|value| value.revision_id),
        task_id: task.task_id,
        repository_instance_id: previous.and_then(|value| value.repository_instance_id),
        worktree_instance_ids: previous
            .map_or_else(Vec::new, |value| value.worktree_instance_ids.clone()),
        active_worktree_instance_id: previous.and_then(|value| value.active_worktree_instance_id),
        worktree_lineage_refs: previous
            .map_or_else(Vec::new, |value| value.worktree_lineage_refs.clone()),
        parent_workstream_id: value.parent_workstream_id,
        dependency_workstream_ids: previous
            .map_or_else(Vec::new, |value| value.dependency_workstream_ids.clone()),
        status: previous.map_or(WorkstreamStatus::Active, |value| value.status),
        root_goal: task.canonical_goal.clone(),
        workstream_goal: value.goal.clone().expect("complete declaration"),
        target_family: value.target_family.clone().expect("complete declaration"),
        hypothesis_or_failure_family: value
            .hypothesis_or_failure_family
            .clone()
            .expect("complete declaration"),
        acceptance_boundary: value
            .acceptance_boundary
            .clone()
            .expect("complete declaration"),
        phase_contract: value.phase_contract.clone().expect("complete declaration"),
        active_episode_id: previous.and_then(|value| value.active_episode_id),
        execution_lane_ids: previous
            .map_or_else(Vec::new, |value| value.execution_lane_ids.clone()),
        source_watermark: watermark,
    }
}

fn work_result(
    request_id: RequestId,
    task: &Task,
    stream: Option<&Workstream>,
    mut warnings: Vec<String>,
    outcome: &str,
) -> Result<McpServiceResult, McpServiceError> {
    warnings.push("agent_claim_plan_not_execution_or_authorization".into());
    let item = |kind: &str, id: String, revision: RevisionId, text: String| McpServiceItem {
        partition: McpItemPartition::Evidence,
        kind: kind.into(),
        object_ref: Some(id),
        object_revision_ref: Some(revision.to_string()),
        source_revision_ref: None,
        scope: Some(task.task_id.to_string()),
        applicability: None,
        authority: Some("none".into()),
        content_trust: ContentTrust::AgentClaim,
        capture_completeness: Some("partial".into()),
        instruction_authority: InstructionAuthority::None,
        text: Some(text),
    };
    let mut items = vec![item("task", task.task_id.to_string(), task.revision_id,
        serde_json::to_string(&serde_json::json!({"outcome":outcome,"goal":task.canonical_goal,"identity_confidence":task.identity_confidence,"source_refs":task.request_root_refs})).map_err(|_| McpServiceError::Store)?)];
    if let Some(stream) = stream {
        items.push(item("workstream", stream.workstream_id.to_string(), stream.revision_id,
            serde_json::to_string(&serde_json::json!({"goal":stream.workstream_goal,"phase":stream.phase_contract,"acceptance":stream.acceptance_boundary})).map_err(|_| McpServiceError::Store)?));
    }
    Ok(passive_result(request_id, items, warnings))
}

fn conflict(request_id: RequestId, task: &Task, stream: Option<&Workstream>) -> McpServiceResult {
    let mut result = work_result(
        request_id,
        task,
        stream,
        vec!["current_revision_conflict_retry_with_current_refs".into()],
        "conflict",
    )
    .unwrap_or_else(|_| invalid(request_id, "current_revision_unavailable"));
    result.status = McpServiceStatus::Conflict;
    result
}

impl McpActionService {
    fn root_sources(
        &self,
        snapshot: &ProjectionSnapshot,
        binding: &McpResolvedScope,
        session: &str,
        refs: &[String],
        budget: &mut Duration,
    ) -> Result<Option<Vec<String>>, McpServiceError> {
        if refs.is_empty() {
            return Ok(None);
        }
        let mut roots = BTreeSet::new();
        for reference in refs {
            let Some((receipt, observation)) = source_pair(snapshot, reference)? else {
                return Ok(None);
            };
            if !submitted(&receipt, &observation, session) {
                return Ok(None);
            }
            if let Some(repository) = receipt.repository_instance_id
                && !repository_visible(
                    snapshot,
                    binding,
                    repository,
                    receipt.worktree_instance_id.as_slice(),
                    budget,
                )?
            {
                return Ok(None);
            }
            roots.insert(observation.source_observation_id.to_string());
        }
        Ok(Some(roots.into_iter().collect()))
    }

    pub(super) async fn work_annotation(
        &self,
        request_id: RequestId,
        binding: McpResolvedScope,
        snapshot: ProjectionSnapshot,
        input: String,
        refs: Vec<String>,
    ) -> Result<McpServiceResult, McpServiceError> {
        let Some(session) = verified_session(&binding) else {
            return Ok(scope_unresolved(request_id));
        };
        let mut trust_budget = crate::repository::SESSION_ROOT_PROBE_BUDGET;
        let key = evertrace_capture::DeviceKeyStore::new(&self.runtime_snapshot.device_key_dir)
            .load()
            .map_err(|_| McpServiceError::Store)?;
        let Ok(mut declaration) = serde_json::from_str::<Declaration>(&input) else {
            return Ok(invalid(request_id, "invalid_work_annotation"));
        };
        declaration.protect(&key)?;
        if declaration.kind != "work_annotation" {
            return Ok(invalid(request_id, "invalid_work_annotation"));
        }
        let Some(roots) =
            self.root_sources(&snapshot, &binding, session, &refs, &mut trust_budget)?
        else {
            return Ok(invalid(request_id, "source_refs_unavailable"));
        };
        let view = WorkIdentityCurrentView::from_snapshot(&snapshot)
            .map_err(|_| McpServiceError::Store)?;
        let current = view.tasks.get(&declaration.task_id);
        if let Some(task) = current
            && !work_visible(&snapshot, &binding, task, &mut trust_budget)?
        {
            return Ok(scope_unresolved(request_id));
        }
        let missing = missing_stream_fields(declaration.workstream.as_ref());
        if declaration.choice == Choice::Fork
            && declaration
                .workstream
                .as_ref()
                .is_none_or(|value| value.parent_workstream_id.is_none())
        {
            return Ok(invalid(request_id, "fork_requires_parent_workstream"));
        }
        if declaration.from_task_id.is_some()
            && (declaration.choice != Choice::Continue
                || current
                    .is_some_and(|task| task.continuation_of_task_id != declaration.from_task_id))
        {
            return Ok(invalid(request_id, "unexpected_continuation_source"));
        }
        if let Some(task) = current {
            if task.lifecycle.is_terminal() {
                return Ok(conflict(
                    request_id,
                    task,
                    declaration
                        .workstream
                        .as_ref()
                        .and_then(|value| view.workstreams.get(&value.workstream_id))
                        .filter(|stream| stream.task_id == task.task_id),
                ));
            }
            let stream_unchanged = declaration.workstream.as_ref().is_none_or(|value| {
                missing.is_empty()
                    && view
                        .workstreams
                        .get(&value.workstream_id)
                        .is_some_and(|stream| stream_matches(stream, value, task))
            });
            if task.canonical_goal == declaration.goal && stream_unchanged {
                return work_result(
                    request_id,
                    task,
                    declaration
                        .workstream
                        .as_ref()
                        .and_then(|value| view.workstreams.get(&value.workstream_id))
                        .filter(|stream| stream.task_id == task.task_id),
                    missing,
                    "no_delta",
                );
            }
            if declaration.choice == Choice::Switch
                || (declaration.choice == Choice::Fork && task.canonical_goal != declaration.goal)
                || ((task.canonical_goal != declaration.goal || missing.is_empty())
                    && declaration.expected_task_revision != Some(task.revision_id))
            {
                return Ok(conflict(
                    request_id,
                    task,
                    declaration
                        .workstream
                        .as_ref()
                        .and_then(|value| view.workstreams.get(&value.workstream_id))
                        .filter(|stream| stream.task_id == task.task_id),
                ));
            }
        } else if declaration.task_id.as_uuid().get_version_num() != 7
            || declaration.expected_task_revision.is_some()
            || matches!(declaration.choice, Choice::Switch | Choice::Fork)
        {
            return Ok(invalid(request_id, "invalid_new_task_target"));
        }
        if declaration.choice == Choice::Continue && current.is_none() {
            let Some(source) = declaration.from_task_id.and_then(|id| view.tasks.get(&id)) else {
                return Ok(invalid(request_id, "continuation_source_missing"));
            };
            if !matches!(
                source.lifecycle,
                TaskLifecycle::Completed | TaskLifecycle::Abandoned
            ) || source.canonical_goal != declaration.goal
                || !work_visible(&snapshot, &binding, source, &mut trust_budget)?
            {
                return Ok(invalid(request_id, "continuation_not_established"));
            }
        }
        let Some(annotation) = self
            .capture_annotation(request_id, &binding, input, (None, None, None))
            .await?
        else {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::Partial,
                "explicit_work_evidence",
                "unknown",
                ["capture_degraded"],
            ));
        };
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| McpServiceError::Store)?;
        let annotation_record = source_pair(&fresh, &annotation.to_string())?;
        if annotation_record
            .as_ref()
            .is_none_or(|(receipt, observation)| {
                receipt.source_session_ref != session
                    || receipt.source_record_identity.as_str() != request_id.to_string()
                    || receipt.source_kind != EvidenceSourceKind::Other
                    || observation.content_trust != ContentTrust::AgentClaim
                    || observation.source_role != SourceRole::Assistant
            })
        {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::Partial,
                "explicit_work_evidence",
                "unknown",
                ["annotation_ingest_pending_retry_same_target"],
            ));
        }
        if self
            .root_sources(&fresh, &binding, session, &refs, &mut trust_budget)?
            .as_ref()
            != Some(&roots)
        {
            return Ok(invalid(request_id, "source_refs_changed"));
        }
        let latest =
            WorkIdentityCurrentView::from_snapshot(&fresh).map_err(|_| McpServiceError::Store)?;
        if latest
            .tasks
            .get(&declaration.task_id)
            .map(|value| value.revision_id)
            != current.map(|value| value.revision_id)
        {
            return Ok(latest.tasks.get(&declaration.task_id).map_or_else(
                || invalid(request_id, "task_changed"),
                |task| conflict(request_id, task, None),
            ));
        }
        if let Some(task) = latest.tasks.get(&declaration.task_id)
            && !work_visible(&fresh, &binding, task, &mut trust_budget)?
        {
            return Ok(scope_unresolved(request_id));
        }
        if current.is_none()
            && let Some(source) = declaration
                .from_task_id
                .and_then(|id| latest.tasks.get(&id))
            && (!matches!(
                source.lifecycle,
                TaskLifecycle::Completed | TaskLifecycle::Abandoned
            ) || source.canonical_goal != declaration.goal
                || !work_visible(&fresh, &binding, source, &mut trust_budget)?)
        {
            return Ok(invalid(request_id, "continuation_source_changed"));
        }
        let now = unix_time_us_for_mcp();
        let context = crate::work::WorkCommandContext {
            command_id: CommandId::new_v7(),
            occurred_at_us: now,
            effective_config_hash: self.runtime_snapshot.effective_config_hash,
            algorithm_revision: "work-annotation-v1",
        };
        let mut task = current.cloned().unwrap_or(Task {
            task_id: declaration.task_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: roots,
            canonical_goal: declaration.goal.clone(),
            scope_memberships: vec![],
            identity_confidence: TaskIdentityConfidence::Provisional,
            lifecycle: TaskLifecycle::Active,
            continuation_of_task_id: declaration.from_task_id,
            split_from_task_id: None,
            split_into_task_ids: vec![],
            merged_from_task_ids: vec![],
            merged_into_task_id: None,
            created_at_us: now,
            closed_at_us: None,
            source_watermark: fresh.frontier,
        });
        let mut events = vec![];
        let evidence = vec![annotation.to_string()];
        if let Some(previous) = current {
            if task.canonical_goal != declaration.goal {
                task.canonical_goal = declaration.goal.clone();
                task.predecessor_revision_id = Some(previous.revision_id);
                task.revision_id = RevisionId::new_v7();
                task.source_watermark = fresh.frontier;
                let Ok(command) = crate::work::task::revise_task(
                    context,
                    previous,
                    task.clone(),
                    crate::work::TypedTaskChange::Goal,
                    &evidence,
                ) else {
                    return Ok(invalid(request_id, "invalid_task_revision"));
                };
                events.extend_from_slice(command.events());
            }
        } else {
            let command = if let Some(source) = declaration
                .from_task_id
                .and_then(|id| latest.tasks.get(&id))
            {
                crate::work::task::continue_task(context, source, task.clone(), &evidence)
            } else {
                crate::work::task::create_task(context, task.clone())
            };
            let Ok(command) = command else {
                return Ok(invalid(request_id, "invalid_task"));
            };
            events.extend_from_slice(command.events());
        }
        let mut stream_result = None;
        if missing.is_empty()
            && let Some(value) = &declaration.workstream
        {
            let repositories =
                evertrace_store::repository::RepositoryCurrentView::from_snapshot(&fresh)
                    .map_err(|_| McpServiceError::Store)?;
            let previous = latest.workstreams.get(&value.workstream_id);
            if previous.is_some_and(|stream| stream.task_id != task.task_id)
                || (previous.is_none() && value.workstream_id.as_uuid().get_version_num() != 7)
                || value.parent_workstream_id.is_some_and(|id| {
                    latest
                        .workstreams
                        .get(&id)
                        .is_none_or(|parent| parent.task_id != task.task_id)
                })
            {
                return Ok(invalid(request_id, "invalid_workstream_target"));
            }
            if previous.map(|stream| stream.revision_id) != value.expected_revision {
                return Ok(current.map_or_else(
                    || invalid(request_id, "invalid_workstream_target"),
                    |task| conflict(request_id, task, previous),
                ));
            }
            let stream = build_stream(value, &task, previous, fresh.frontier);
            let command = if let Some(previous) = previous {
                crate::work::workstream::revise_workstream(
                    context,
                    &task,
                    &repositories,
                    previous,
                    stream.clone(),
                    crate::work::TypedWorkstreamChange::StructuredRevision,
                    &evidence,
                )
            } else {
                crate::work::workstream::create_workstream(
                    context,
                    &task,
                    &repositories,
                    stream.clone(),
                )
            };
            let Ok(command) = command else {
                return Ok(invalid(request_id, "invalid_workstream"));
            };
            events.extend_from_slice(command.events());
            stream_result = Some(stream);
        }
        for event in &mut events {
            event.causation_id = Some(annotation.to_string());
        }
        let annotation_only = events.is_empty();
        if !events.is_empty() {
            let command = JournalCommand::new(context.command_id, events)
                .map_err(|_| McpServiceError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, now, fresh.frontier)
                .await
            {
                Ok(_) => (),
                Err(WriterActorError::StaleFrontier) => {
                    let snapshot = self
                        .writer
                        .project()
                        .await
                        .map_err(|_| McpServiceError::Store)?;
                    let current = WorkIdentityCurrentView::from_snapshot(&snapshot)
                        .map_err(|_| McpServiceError::Store)?;
                    return Ok(current.tasks.get(&task.task_id).map_or_else(
                        || {
                            let mut result =
                                invalid(request_id, "frontier_changed_retry_same_target");
                            result.status = McpServiceStatus::Conflict;
                            result
                        },
                        |task| {
                            conflict(
                                request_id,
                                task,
                                declaration.workstream.as_ref().and_then(|value| {
                                    current
                                        .workstreams
                                        .get(&value.workstream_id)
                                        .filter(|stream| stream.task_id == task.task_id)
                                }),
                            )
                        },
                    ));
                }
                Err(_) => return Err(McpServiceError::Store),
            }
        }
        work_result(
            request_id,
            &task,
            stream_result.as_ref(),
            missing,
            if annotation_only {
                "annotation_only"
            } else {
                "recorded_agent_claim"
            },
        )
    }

    pub(super) async fn passive_work_read(
        &self,
        request_id: RequestId,
        action: McpServiceAction,
        binding: McpResolvedScope,
        snapshot: ProjectionSnapshot,
        input: String,
        refs: Vec<String>,
    ) -> Result<McpServiceResult, McpServiceError> {
        let Some(session) = verified_session(&binding) else {
            return Ok(scope_unresolved(request_id));
        };
        let mut trust_budget = crate::repository::SESSION_ROOT_PROBE_BUDGET;
        if !matches!(action, McpServiceAction::Search | McpServiceAction::Get) || input == "@due" {
            return Ok(scope_unresolved(request_id));
        }
        let view = WorkIdentityCurrentView::from_snapshot(&snapshot)
            .map_err(|_| McpServiceError::Store)?;
        let requested = if action == McpServiceAction::Get
            || input.parse::<TaskId>().is_ok()
            || input.parse::<WorkstreamId>().is_ok()
        {
            vec![input.clone()]
        } else {
            refs
        };
        let mut items = vec![];
        let mut truncated = false;
        let mut next_refs = vec![];
        if requested.is_empty() {
            // Current rows already contain canonical, validated payloads. This
            // lexical prefilter only avoids decoding unrelated sessions; typed
            // membership below is the authority check. Keep only a bounded
            // recent window, without retaining every historical body.
            let needle = format!(
                "\"source_session_ref\":{}",
                serde_json::to_string(session).map_err(|_| McpServiceError::Store)?
            );
            let mut recent = BTreeMap::new();
            for row in snapshot.data_rows().filter(|row| {
                row.object_kind.as_deref() == Some("source_receipt")
                    && row.payload_json.as_deref().is_some_and(|json| {
                        json.contains(&needle)
                            && json.contains("\"source_kind\":\"codex_hook\"")
                            && json.contains("\"observation_role\":\"message\"")
                    })
            }) {
                recent.insert((row.source_event_seq, row.row_id.as_str()), row);
                if recent.len() > 32 {
                    recent.pop_first();
                    truncated = true;
                }
            }
            let mut remaining = 8 * 1024 * 1024usize;
            for (_, row) in recent.into_iter().rev() {
                let Some(reference) = &row.object_id else {
                    continue;
                };
                let bytes = row.payload_json.as_ref().map_or(0, String::len);
                if bytes > remaining {
                    truncated = true;
                    next_refs.push(reference.clone());
                    break;
                }
                remaining -= bytes;
                let Some((receipt, observation)) = source_pair(&snapshot, reference)? else {
                    continue;
                };
                if !submitted(&receipt, &observation, session) {
                    continue;
                }
                if let Some(repository) = receipt.repository_instance_id
                    && !repository_visible(
                        &snapshot,
                        &binding,
                        repository,
                        receipt.worktree_instance_id.as_slice(),
                        &mut trust_budget,
                    )?
                {
                    continue;
                }
                let text = presentation_text(&receipt);
                if !text.to_lowercase().contains(&input.to_lowercase()) {
                    continue;
                }
                items.push(evidence_item(row, text, ContentTrust::Observed));
                if items.len() == 3 {
                    truncated = true;
                    break;
                }
            }
        } else {
            for reference in requested.iter().take(3) {
                let Some((row, true)) = select_object_row(&snapshot, reference).ok().flatten()
                else {
                    continue;
                };
                let task = reference
                    .parse::<TaskId>()
                    .ok()
                    .and_then(|id| view.tasks.get(&id))
                    .or_else(|| {
                        reference
                            .parse::<WorkstreamId>()
                            .ok()
                            .and_then(|id| view.workstreams.get(&id))
                            .and_then(|stream| view.tasks.get(&stream.task_id))
                    });
                if let Some(task) = task {
                    if !work_visible(&snapshot, &binding, task, &mut trust_budget)? {
                        continue;
                    }
                    if let Some(stream) = reference
                        .parse::<WorkstreamId>()
                        .ok()
                        .and_then(|id| view.workstreams.get(&id))
                        && let Some(repository) = stream.repository_instance_id
                        && !repository_visible(
                            &snapshot,
                            &binding,
                            repository,
                            &stream.worktree_instance_ids,
                            &mut trust_budget,
                        )?
                    {
                        continue;
                    }
                    if let Some(detail) =
                        super::super::human_governance::work_evidence_detail(&snapshot, row)
                            .map_err(|_| McpServiceError::Store)?
                    {
                        items.push(evidence_item(
                            row,
                            serde_json::to_string(&detail).map_err(|_| McpServiceError::Store)?,
                            ContentTrust::AgentClaim,
                        ));
                    }
                } else if let Some((receipt, observation)) = source_pair(&snapshot, reference)?
                    && submitted(&receipt, &observation, session)
                {
                    if let Some(repository) = receipt.repository_instance_id
                        && !repository_visible(
                            &snapshot,
                            &binding,
                            repository,
                            receipt.worktree_instance_id.as_slice(),
                            &mut trust_budget,
                        )?
                    {
                        continue;
                    }
                    items.push(evidence_item(
                        row,
                        presentation_text(&receipt),
                        ContentTrust::Observed,
                    ));
                }
            }
        }
        let mut result = passive_result(
            request_id,
            items,
            vec!["evidence_only_no_active_work_binding".into()],
        );
        result.truncated = truncated;
        result.next_refs = next_refs;
        if truncated {
            result
                .warnings
                .push("bounded_session_submission_window".into());
        }
        Ok(result)
    }
}

fn presentation_text(receipt: &evertrace_domain::evidence::SourceReceipt) -> String {
    serde_json::to_string(&serde_json::json!({"protected_presentation":super::super::human_governance::bounded_evidence_presentation(receipt.protected_presentation.clone()),
        "protected_length":receipt.protected_length,"cas_ref":receipt.cas_ref})).unwrap_or_default()
}

fn evidence_item(row: &ObjectRow, text: String, trust: ContentTrust) -> McpServiceItem {
    McpServiceItem {
        partition: McpItemPartition::Evidence,
        kind: row.object_kind.clone().unwrap_or_default(),
        object_ref: row.object_id.clone(),
        object_revision_ref: row.current_revision_id.clone(),
        source_revision_ref: None,
        scope: Some("explicit_evidence_only".into()),
        applicability: None,
        authority: Some("none".into()),
        content_trust: trust,
        capture_completeness: Some("partial".into()),
        instruction_authority: InstructionAuthority::None,
        text: Some(text),
    }
}
