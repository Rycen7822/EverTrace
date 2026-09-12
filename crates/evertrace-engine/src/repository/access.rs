//! Orthogonal durable repository gates shared by live reads and background work.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use evertrace_domain::{
    ids::{CommandId, RepositoryId},
    repository::RepositoryInstance,
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload};

/// Inventory freshness is deliberately absent: pending asset discovery must
/// not invalidate independently authorized source-only L0 or archived CAS.
pub(crate) fn repository_read_gate(repository: &RepositoryInstance, purged: bool) -> bool {
    !purged
        && !repository.user_disabled
        && !repository
            .capability_state
            .as_ref()
            .is_some_and(|state| state.trust_revoked)
}

/// Physical Task/Worktree-scoped rows need not duplicate a repository column.
/// Resolve only the selected rows' direct typed scope references, once per
/// request, from the same current projection; never infer scope from a path.
pub(crate) fn row_repository_contexts<'a>(
    snapshot: &evertrace_store::ProjectionSnapshot,
    rows: &[&'a evertrace_store::ObjectRow],
) -> Result<std::collections::BTreeMap<&'a str, BTreeSet<RepositoryId>>, crate::WriterActorError> {
    let requested = rows
        .iter()
        .flat_map(|row| [row.task_id.as_deref(), row.worktree_id.as_deref()])
        .flatten()
        .collect::<BTreeSet<_>>();
    let mut scopes = std::collections::BTreeMap::<&str, BTreeSet<RepositoryId>>::new();
    for row in snapshot.data_rows().filter(|row| {
        matches!(row.object_kind.as_deref(), Some("task" | "worktree"))
            && row
                .object_id
                .as_deref()
                .is_some_and(|id| requested.contains(id))
    }) {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(crate::WriterActorError::StoreCorrupt)?,
        )
        .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
        let ids = match payload {
            JournalPayload::TaskRecorded(task) => task
                .scope_memberships
                .iter()
                .filter_map(|scope| scope.repository_instance_id)
                .collect(),
            JournalPayload::WorktreeInstanceRecorded(worktree) => {
                [worktree.repository_instance_id].into_iter().collect()
            }
            _ => return Err(crate::WriterActorError::StoreCorrupt),
        };
        if scopes
            .insert(row.object_id.as_deref().unwrap(), ids)
            .is_some()
        {
            return Err(crate::WriterActorError::StoreCorrupt);
        }
    }
    let mut result = std::collections::BTreeMap::new();
    for row in rows {
        let mut ids = BTreeSet::new();
        if let Some(id) = &row.repository_id {
            ids.insert(
                id.parse()
                    .map_err(|_| crate::WriterActorError::StoreCorrupt)?,
            );
        }
        for reference in [row.task_id.as_deref(), row.worktree_id.as_deref()]
            .into_iter()
            .flatten()
        {
            ids.extend(
                scopes
                    .get(reference)
                    .ok_or(crate::WriterActorError::StoreCorrupt)?,
            );
        }
        result.insert(row.row_id.as_str(), ids);
    }
    Ok(result)
}

/// Persist an actual Untrusted observation against the exact repository facts
/// used to resolve its trust locator. Concurrent identity/permission changes
/// require a new observation; a stale result cannot revoke a different instance.
pub(crate) async fn record_trust_revocations(
    writer: &crate::WriterHandle,
    observed: Vec<RepositoryInstance>,
    config_hash: [u8; 32],
) -> Result<bool, crate::WriterActorError> {
    if observed.is_empty() {
        return Ok(false);
    }
    let ids = observed
        .iter()
        .map(|repository| repository.repository_id)
        .collect();
    let context = writer.repository_read_context(ids).await?;
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_micros()).ok())
        .ok_or(crate::WriterActorError::InvalidInput)?;
    let mut payloads = std::collections::BTreeMap::new();
    for repository in observed {
        let Some(current) = context.repositories.get(&repository.repository_id) else {
            return Err(crate::WriterActorError::InvalidInput);
        };
        if context.purged.contains(&repository.repository_id)
            || current
                .capability_state
                .as_ref()
                .is_some_and(|state| state.trust_revoked)
        {
            continue;
        }
        if current != &repository {
            return Err(crate::WriterActorError::InvalidInput);
        }
        let mut successor = repository;
        successor.predecessor_revision = Some(successor.repository_revision);
        successor.repository_revision = successor
            .repository_revision
            .checked_add(1)
            .ok_or(crate::WriterActorError::InvalidInput)?;
        successor.recorded_at_us = at;
        successor
            .capability_state
            .get_or_insert(evertrace_domain::repository::RepositoryCapabilityState {
                trust_revoked: false,
                revalidated_inventory_ref: None,
            })
            .trust_revoked = true;
        payloads.insert(
            successor.repository_id,
            JournalPayload::RepositoryInstanceRecorded(Box::new(successor)),
        );
    }
    if payloads.is_empty() {
        return Ok(false);
    }
    let command = JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_values()
            .map(|payload| {
                JournalEventDraft::runtime(at, config_hash, "repository-read-v1", payload)
            })
            .collect(),
    )
    .map_err(|_| crate::WriterActorError::InvalidInput)?;
    let id = command.command_id();
    let expected = command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    if let Err(error) = writer
        .commit_if_frontier(command, at, context.frontier)
        .await
        && !writer
            .committed_command(id)
            .await?
            .is_some_and(|done| done.payloads == expected)
    {
        return Err(error);
    }
    Ok(true)
}

/// One current actor read and one bounded decision per referenced repository,
/// shared by candidate consumers. It never reads an inventory or source JSONL.
pub(crate) async fn blocked_repositories(
    writer: &crate::WriterHandle,
    ids: BTreeSet<RepositoryId>,
    report: Option<&evertrace_codex::probe::HostProbeReport>,
    config_hash: [u8; 32],
) -> Result<BTreeSet<RepositoryId>, crate::WriterActorError> {
    blocked_repositories_before(
        writer,
        ids,
        report,
        config_hash,
        Instant::now() + Duration::from_millis(250),
    )
    .await
}

pub(crate) async fn blocked_repositories_before(
    writer: &crate::WriterHandle,
    ids: BTreeSet<RepositoryId>,
    report: Option<&evertrace_codex::probe::HostProbeReport>,
    config_hash: [u8; 32],
    deadline: Instant,
) -> Result<BTreeSet<RepositoryId>, crate::WriterActorError> {
    if ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let context = writer.repository_read_context(ids.clone()).await?;
    let observed_location = report
        .and_then(|report| report.inventory_host())
        .and_then(|host| {
            super::workspace_git_location(&host.cwd, deadline)
                .ok()
                .flatten()
        });
    let mut blocked = BTreeSet::new();
    let mut revoked = Vec::new();
    for id in ids {
        let Some(repository) = context.repositories.get(&id) else {
            blocked.insert(id);
            continue;
        };
        let locator = observed_location
            .as_ref()
            .filter(|location| {
                repository.common_dir_filesystem == Some(location.common_dir_filesystem)
            })
            .and_then(|location| location.worktree_path.to_str())
            .unwrap_or(&repository.current_path);
        let trust = report.map(|report| {
            super::read_report_path_trust_before(report, Some(locator), deadline).state
        });
        if !repository_read_gate(repository, context.purged.contains(&id))
            || trust != Some(evertrace_codex::policy::RepositoryTrustState::Trusted)
        {
            blocked.insert(id);
        }
        if !context.purged.contains(&id)
            && trust == Some(evertrace_codex::policy::RepositoryTrustState::Untrusted)
            && !repository
                .capability_state
                .as_ref()
                .is_some_and(|state| state.trust_revoked)
        {
            revoked.push(repository.clone());
        }
    }
    record_trust_revocations(writer, revoked, config_hash).await?;
    Ok(blocked)
}

/// Current finite assets are read from protected CAS only after matching the
/// original verified context and the repository's current restoration boundary.
pub(crate) async fn read_inventory(
    writer: &crate::WriterHandle,
    bindings: &crate::McpBindingAuthority,
    runtime: &evertrace_capture::RuntimeSnapshot,
    fact: &evertrace_domain::inventory::CapabilityInventoryRecorded,
) -> Result<Option<evertrace_domain::inventory::CapabilityInventorySnapshot>, crate::WriterActorError>
{
    read_inventory_before(
        writer,
        bindings,
        runtime,
        fact,
        Instant::now() + Duration::from_millis(250),
    )
    .await
}

pub(crate) async fn read_inventory_before(
    writer: &crate::WriterHandle,
    bindings: &crate::McpBindingAuthority,
    runtime: &evertrace_capture::RuntimeSnapshot,
    fact: &evertrace_domain::inventory::CapabilityInventoryRecorded,
    deadline: Instant,
) -> Result<Option<evertrace_domain::inventory::CapabilityInventorySnapshot>, crate::WriterActorError>
{
    let context = writer.inventory_context(&fact.context, None).await?;
    let completion = context.post_restoration_completion();
    if completion.is_none_or(|current| current.job_id != fact.job_id) {
        // Inspecting a historical fact must not repeatedly rescan a context
        // that already has a valid newer completion. A closed user/revocation
        // gate also waits for the explicit enable operation, not a read.
        if completion.is_none()
            && context.repository.as_ref().is_some_and(|repository| {
                repository_read_gate(repository, context.purge_pending_or_purged)
            })
        {
            bindings.inventory_context_stale(&fact.context);
        }
        return Ok(None);
    }
    let Some(host) =
        inventory_read_gate(writer, bindings, runtime, &fact.context, deadline).await?
    else {
        return Ok(None);
    };
    let snapshot = read_inventory_snapshot(&runtime.cas_dir, fact)?;
    if !host.current_before(deadline)
        || !crate::jobs::inventory_snapshot_current(&snapshot, deadline)
    {
        bindings.inventory_context_stale(&fact.context);
        return Ok(None);
    }
    if inventory_read_gate(writer, bindings, runtime, &fact.context, deadline)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let final_context = writer.inventory_context(&fact.context, None).await?;
    if final_context.post_restoration_completion() != Some(fact) || !host.current_before(deadline) {
        return Ok(None);
    }
    Ok(Some(snapshot))
}

// Live authorization only: old CAS must not trigger a second scan of current
// assets. Both readers retain the same Host, trust and restoration gates.
async fn inventory_read_gate(
    writer: &crate::WriterHandle,
    bindings: &crate::McpBindingAuthority,
    runtime: &evertrace_capture::RuntimeSnapshot,
    context: &evertrace_domain::inventory::InventoryContext,
    deadline: Instant,
) -> Result<Option<std::sync::Arc<super::NativeHostContext>>, crate::WriterActorError> {
    if Instant::now() >= deadline
        || writer
            .inventory_context(context, None)
            .await?
            .post_restoration_completion()
            .is_none()
    {
        return Ok(None);
    }
    let observed = bindings
        .active_inventory_contexts()
        .into_iter()
        .find(|(host, report)| {
            Instant::now() < deadline
                && host.cwd.to_str() == Some(context.cwd.as_str())
                && host.home.to_str() == Some(context.host_home.as_str())
                && host.config_root.to_str() == Some(context.host_config_root.as_str())
                && host.profile == context.host_profile
                && report.manifest().adapter_manifest_id == context.adapter_manifest_id
                && host.selections_observed
                && host.current_before(deadline)
        });
    let Some((host, report)) = observed else {
        return Ok(None);
    };
    if !blocked_repositories_before(
        writer,
        [context.repository_id].into_iter().collect(),
        Some(&report),
        runtime.effective_config_hash,
        deadline,
    )
    .await?
    .is_empty()
    {
        return Ok(None);
    }
    Ok((Instant::now() < deadline).then_some(host))
}

/// Read an already committed session-time completion. Current authorization
/// and a restored current completion remain necessary, but current asset bytes
/// cannot rewrite the capabilities observed before the source boundary.
pub(crate) async fn read_procedure_historical_inventory(
    writer: &crate::WriterHandle,
    bindings: &crate::McpBindingAuthority,
    runtime: &evertrace_capture::RuntimeSnapshot,
    projection: &evertrace_store::ProjectionSnapshot,
    fact: &evertrace_domain::inventory::CapabilityInventoryRecorded,
    source: (&str, (u64, i64)),
    deadline: Instant,
) -> Result<Option<evertrace_domain::inventory::CapabilityInventorySnapshot>, crate::WriterActorError>
{
    let (session, boundary) = source;
    if fact.recorded_at_us > boundary.1
        || !fact
            .evidence_refs
            .iter()
            .any(|reference| reference == session)
    {
        return Ok(None);
    }
    let fact_id = fact.job_id.to_string();
    let Some(row) = projection
        .data_rows()
        .take_while(|_| Instant::now() < deadline)
        .find(|row| {
            row.object_kind.as_deref() == Some("capability_inventory")
                && row.object_id.as_deref() == Some(fact_id.as_str())
                && row.source_event_seq <= boundary.0
        })
    else {
        return Ok(None);
    };
    let committed: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(crate::WriterActorError::StoreCorrupt)?,
    )
    .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
    if !matches!(committed, JournalPayload::CapabilityInventoryRecorded(ref value) if value.as_ref() == fact)
    {
        return Err(crate::WriterActorError::StoreCorrupt);
    }
    let current = writer.inventory_context(&fact.context, None).await?;
    let Some(completion) = current.post_restoration_completion() else {
        return Ok(None);
    };
    let Some(host) =
        inventory_read_gate(writer, bindings, runtime, &fact.context, deadline).await?
    else {
        return Ok(None);
    };
    let snapshot = read_inventory_snapshot(&runtime.cas_dir, fact)?;
    if inventory_read_gate(writer, bindings, runtime, &fact.context, deadline)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let after = writer.inventory_context(&fact.context, None).await?;
    if after.post_restoration_completion() != Some(completion)
        || after.repository != current.repository
        || !host.current_before(deadline)
    {
        return Ok(None);
    }
    Ok(Some(snapshot))
}

pub(crate) fn read_inventory_snapshot(
    cas_dir: &std::path::Path,
    fact: &evertrace_domain::inventory::CapabilityInventoryRecorded,
) -> Result<evertrace_domain::inventory::CapabilityInventorySnapshot, crate::WriterActorError> {
    let cas = evertrace_capture::CasStore::open_existing(cas_dir)
        .map_err(|_| crate::WriterActorError::Store)?;
    let digest = fact
        .snapshot_cas_ref
        .parse()
        .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
    let (bytes, _) = cas
        .read_bounded(&digest, 8 * 1024 * 1024, 8 * 1024 * 1024)
        .map_err(|_| crate::WriterActorError::Store)?;
    let snapshot: evertrace_domain::inventory::CapabilityInventorySnapshot =
        serde_json::from_slice(&bytes).map_err(|_| crate::WriterActorError::StoreCorrupt)?;
    snapshot
        .validate()
        .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
    let refs = snapshot
        .signatures
        .iter()
        .map(|signature| signature.content_cas_ref.as_str())
        .collect::<BTreeSet<_>>();
    if refs
        != fact
            .dependency_cas_refs
            .iter()
            .map(String::as_str)
            .collect()
    {
        return Err(crate::WriterActorError::StoreCorrupt);
    }
    Ok(snapshot)
}
