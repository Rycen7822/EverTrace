use super::{
    RECOVERY_ALGORITHM_REVISION, RecoveryBudget, RecoveryCaptureFacts, RecoveryError,
    RecoveryItemKind,
};
use evertrace_capture::{CasStore, DeviceKeyStore, protect};
use evertrace_domain::evidence::hex;
use evertrace_domain::{
    ids::{CommandId, RecoveryBundleId},
    repository::{
        OrderingIntegrity, RecoveryBundle, RecoveryCaptureRequest, RecoveryCaptureStatus,
        RecoveryContentRef, RecoveryOmission, RecoveryOmissionReason, RecoveryProtectedRef,
        RecoveryRequestStatus, SUPPORTED_MUTATION_DOMAIN, WorktreeSnapshot,
    },
};
use evertrace_store::projections::RecoveryCurrentView;
use evertrace_store::{EventScope, JournalCommand, JournalEventDraft, JournalPayload, SourceKind};
use std::time::Instant;

pub fn capture_recovery_bundle(
    facts: RecoveryCaptureFacts,
    budget: RecoveryBudget,
    cas: &CasStore,
    keys: &DeviceKeyStore,
) -> Result<RecoveryBundle, RecoveryError> {
    capture_recovery_bundle_until(facts, budget, cas, keys, None)
}

pub(super) fn capture_recovery_bundle_until(
    facts: RecoveryCaptureFacts,
    budget: RecoveryBudget,
    cas: &CasStore,
    keys: &DeviceKeyStore,
    deadline: Option<Instant>,
) -> Result<RecoveryBundle, RecoveryError> {
    if budget.max_item_bytes == 0
        || budget.max_untracked_item_bytes == 0
        || budget.max_bundle_bytes == 0
    {
        return Err(RecoveryError::InvalidInput);
    }
    facts
        .snapshot
        .validate()
        .map_err(|_| RecoveryError::InvalidInput)?;
    let key = keys.load().map_err(|_| RecoveryError::Protection)?;
    let mut bundle = RecoveryBundle {
        recovery_bundle_id: RecoveryBundleId::new_v7(),
        source_worktree_instance_id: facts.snapshot.worktree_instance_id,
        source_snapshot_id: facts.snapshot.worktree_snapshot_id,
        trigger_request_ids: vec![facts.request_id],
        tracked_diff_blob_refs: Vec::new(),
        tracked_file_blob_refs: Vec::new(),
        index_state_refs: Vec::new(),
        untracked_file_blob_refs: Vec::new(),
        untracked_work_artifact_refs: facts.artifact_refs,
        metadata_only_work_artifact_refs: facts.metadata_artifact_refs,
        config_and_run_refs: facts.config_and_run_refs,
        attempt_anchor_ids: facts.attempt_anchor_ids,
        attempt_anchor_claims: Vec::new(),
        omissions: facts.omissions,
        capture_status: RecoveryCaptureStatus::Complete,
        ordering_integrity: OrderingIntegrity::Complete,
        adapter_manifest_id: facts.adapter_manifest_id,
        eligible_mutation_manifest_version: facts.mutation_manifest_version,
        eligible_mutation_domain: SUPPORTED_MUTATION_DOMAIN.into(),
        captured_bytes: 0,
        captured_at_us: facts.captured_at_us,
    };
    for item in facts.items {
        if deadline.is_some_and(|value| Instant::now() >= value) {
            if !bundle
                .omissions
                .iter()
                .any(|value| value.item_ref == "recovery_barrier_deadline")
            {
                bundle.omissions.push(RecoveryOmission {
                    item_ref: "recovery_barrier_deadline".into(),
                    reason: RecoveryOmissionReason::TimeBudgetExceeded,
                    metadata_ref: None,
                });
            }
            bundle.ordering_integrity = OrderingIntegrity::BestEffort;
            break;
        }
        if item.metadata_only {
            bundle.omissions.push(RecoveryOmission {
                item_ref: item.item_ref,
                reason: RecoveryOmissionReason::UnsupportedKind,
                metadata_ref: Some("metadata_only".into()),
            });
            continue;
        }
        let item_len = u64::try_from(item.bytes.len()).map_err(|_| RecoveryError::Budget)?;
        if item_len == 0
            && !matches!(
                item.kind,
                RecoveryItemKind::TrackedFile | RecoveryItemKind::UntrackedFile
            )
        {
            if item.critical {
                bundle.omissions.push(RecoveryOmission {
                    item_ref: item.item_ref,
                    reason: critical_reason(item.kind),
                    metadata_ref: None,
                });
            }
            continue;
        }
        let item_limit = if item.kind == RecoveryItemKind::UntrackedFile {
            budget.max_untracked_item_bytes
        } else {
            budget.max_item_bytes
        };
        if item_len > item_limit {
            bundle.omissions.push(RecoveryOmission {
                item_ref: item.item_ref,
                reason: RecoveryOmissionReason::FileTooLarge,
                metadata_ref: None,
            });
            continue;
        }
        let protected = protect(&item.bytes, &key).map_err(|_| RecoveryError::Protection)?;
        let protected_len =
            u64::try_from(protected.protected_bytes().len()).map_err(|_| RecoveryError::Budget)?;
        let path_protected = match item.kind {
            RecoveryItemKind::TrackedFile | RecoveryItemKind::UntrackedFile => Some(
                protect(
                    item.relative_path
                        .as_deref()
                        .ok_or(RecoveryError::InvalidBundle)?,
                    &key,
                )
                .map_err(|_| RecoveryError::Protection)?,
            ),
            _ if item.relative_path.is_none() => None,
            _ => return Err(RecoveryError::InvalidBundle),
        };
        let path_protected_len = path_protected
            .as_ref()
            .map(|value| u64::try_from(value.protected_bytes().len()))
            .transpose()
            .map_err(|_| RecoveryError::Budget)?
            .unwrap_or(0);
        let total_protected_len = protected_len
            .checked_add(path_protected_len)
            .ok_or(RecoveryError::Budget)?;
        if bundle
            .captured_bytes
            .checked_add(total_protected_len)
            .is_none_or(|value| value > budget.max_bundle_bytes)
        {
            bundle.omissions.push(RecoveryOmission {
                item_ref: item.item_ref,
                reason: RecoveryOmissionReason::BundleBudgetExceeded,
                metadata_ref: None,
            });
            continue;
        }
        let payload = protected_ref(&protected, cas)?;
        let protected_relative_path = path_protected
            .as_ref()
            .map(|value| protected_ref(value, cas))
            .transpose()?;
        let item_ref = item.item_ref;
        let reference = RecoveryContentRef {
            item_ref: item_ref.clone(),
            payload,
            protected_relative_path,
        };
        if reference.payload.protected_secret_digest.is_some()
            || reference
                .protected_relative_path
                .as_ref()
                .is_some_and(|value| value.protected_secret_digest.is_some())
        {
            bundle.omissions.push(RecoveryOmission {
                item_ref,
                reason: RecoveryOmissionReason::SecretRedacted,
                metadata_ref: Some("protected_secret_digest".into()),
            });
        }
        bundle.captured_bytes = bundle
            .captured_bytes
            .checked_add(total_protected_len)
            .ok_or(RecoveryError::Budget)?;
        match item.kind {
            RecoveryItemKind::TrackedDiff => bundle.tracked_diff_blob_refs.push(reference),
            RecoveryItemKind::TrackedFile => bundle.tracked_file_blob_refs.push(reference),
            RecoveryItemKind::IndexState => bundle.index_state_refs.push(reference),
            RecoveryItemKind::UntrackedFile => bundle.untracked_file_blob_refs.push(reference),
        }
    }
    match (facts.before_fingerprint, facts.after_fingerprint) {
        (Some(before), Some(after)) if before == after => {}
        (Some(_), Some(_)) => {
            bundle.ordering_integrity = OrderingIntegrity::Raced;
            bundle.omissions.push(RecoveryOmission {
                item_ref: "worktree_mutation_fence".into(),
                reason: RecoveryOmissionReason::ConcurrentChange,
                metadata_ref: None,
            });
        }
        _ => {
            bundle.ordering_integrity = OrderingIntegrity::BestEffort;
            bundle.omissions.push(RecoveryOmission {
                item_ref: "worktree_mutation_fence".into(),
                reason: RecoveryOmissionReason::Unreadable,
                metadata_ref: None,
            });
        }
    }
    if !bundle.omissions.is_empty() || bundle.ordering_integrity != OrderingIntegrity::Complete {
        bundle.capture_status = RecoveryCaptureStatus::Partial;
    }
    bundle
        .validate()
        .map_err(|_| RecoveryError::InvalidBundle)?;
    Ok(bundle)
}

pub(super) fn protected_ref(
    protected: &evertrace_capture::ProtectedPayload,
    cas: &CasStore,
) -> Result<RecoveryProtectedRef, RecoveryError> {
    Ok(RecoveryProtectedRef {
        cas_ref: cas.put(protected).map_err(|_| RecoveryError::Cas)?.as_hex(),
        protected_length: u64::try_from(protected.protected_bytes().len())
            .map_err(|_| RecoveryError::Budget)?,
        original_length: protected.raw_length(),
        protected_secret_digest: protected.protected_secret_digest().map(|value| hex(&value)),
        redaction_spans: u32::try_from(protected.spans().len())
            .map_err(|_| RecoveryError::Protection)?,
    })
}

fn critical_reason(kind: RecoveryItemKind) -> RecoveryOmissionReason {
    match kind {
        RecoveryItemKind::IndexState => RecoveryOmissionReason::CriticalIndexStateMissing,
        RecoveryItemKind::TrackedDiff | RecoveryItemKind::TrackedFile => {
            RecoveryOmissionReason::CriticalTrackedStateMissing
        }
        RecoveryItemKind::UntrackedFile => RecoveryOmissionReason::AttemptAnchorMissing,
    }
}

pub fn pending_request_command(
    command_id: CommandId,
    request: RecoveryCaptureRequest,
) -> Result<JournalCommand, RecoveryError> {
    if request.request_status != RecoveryRequestStatus::Pending {
        return Err(RecoveryError::InvalidInput);
    }
    recovery_command(
        command_id,
        request.started_at_us,
        request.effective_config_hash,
        request.repository_instance_id.to_string(),
        request.worktree_instance_id.to_string(),
        vec![JournalPayload::RecoveryCaptureRequestRecorded(Box::new(
            request,
        ))],
    )
}

pub fn terminal_capture_command(
    command_id: CommandId,
    current: &RecoveryCurrentView,
    terminal: RecoveryCaptureRequest,
    snapshot: Option<WorktreeSnapshot>,
    bundle: Option<RecoveryBundle>,
) -> Result<JournalCommand, RecoveryError> {
    let pending = current
        .state
        .requests
        .get(&terminal.recovery_capture_request_id)
        .ok_or(RecoveryError::StaleCurrent)?;
    if !terminal.is_successor_of(pending) || !terminal.request_status.is_terminal() {
        return Err(RecoveryError::InvalidSuccessor);
    }
    if bundle.as_ref().map(|value| value.recovery_bundle_id) != terminal.recovery_bundle_id
        || snapshot.as_ref().map(|value| value.worktree_snapshot_id)
            != terminal.pre_operation_snapshot_id
        || bundle.as_ref().is_some_and(|value| {
            Some(value.source_snapshot_id)
                != snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.worktree_snapshot_id)
        })
    {
        return Err(RecoveryError::InvalidInput);
    }
    let mut payloads = Vec::new();
    if let Some(snapshot) = snapshot {
        payloads.push(JournalPayload::WorktreeSnapshotRecorded(Box::new(snapshot)));
    }
    payloads.push(JournalPayload::RecoveryCaptureRequestRecorded(Box::new(
        terminal.clone(),
    )));
    if let Some(bundle) = bundle {
        payloads.push(JournalPayload::RecoveryBundleRecorded(Box::new(bundle)));
    }
    recovery_command(
        command_id,
        terminal.finished_at_us.ok_or(RecoveryError::InvalidInput)?,
        terminal.effective_config_hash,
        terminal.repository_instance_id.to_string(),
        terminal.worktree_instance_id.to_string(),
        payloads,
    )
}

fn recovery_command(
    command_id: CommandId,
    occurred_at_us: i64,
    effective_config_hash: [u8; 32],
    repository_id: String,
    worktree_id: String,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, RecoveryError> {
    let events = payloads
        .into_iter()
        .map(|payload| JournalEventDraft {
            occurred_at_us,
            source_kind: SourceKind::System,
            scope: EventScope {
                repository_id: (!repository_id.is_empty()).then(|| repository_id.clone()),
                worktree_id: Some(worktree_id.clone()),
                ..EventScope::default()
            },
            causation_id: None,
            correlation_id: None,
            effective_config_hash,
            algorithm_revision: RECOVERY_ALGORITHM_REVISION.into(),
            payload,
        })
        .collect();
    JournalCommand::new(command_id, events).map_err(Into::into)
}
