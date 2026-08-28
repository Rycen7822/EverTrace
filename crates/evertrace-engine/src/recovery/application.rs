use super::barrier::current_time_us;
use super::{RECOVERY_ALGORITHM_REVISION, RecoveryError};
use crate::WriterHandle;
use evertrace_capture::{
    CasDigest, CasStore, DeviceKeyStore, recovery_ticket_auth_tag, verify_recovery_ticket_auth_tag,
};
use evertrace_domain::{
    canonical::CanonicalValue,
    ids::{RecoveryApplicationId, RecoveryBundleId, WorktreeId, WorktreeSnapshotId},
    repository::{RecoveryApplicationKind, RecoveryBundle, RecoveryContentRef, WorktreeLifecycle},
};
use evertrace_store::{projections::RecoveryCurrentView, repository::RepositoryCurrentView};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, str::FromStr};

pub const RECOVERY_APPLICATION_TICKET_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApplicationTicketClaims {
    pub ticket_version: u16,
    pub prospective_recovery_application_id: RecoveryApplicationId,
    pub recovery_bundle_id: RecoveryBundleId,
    pub selected_content_refs: Vec<RecoveryContentRef>,
    pub application_kind: RecoveryApplicationKind,
    pub target_worktree_instance_id: WorktreeId,
    pub pre_application_snapshot_id: WorktreeSnapshotId,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: String,
    pub issued_at_us: i64,
    pub device_key_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApplicationTicket {
    pub claims: RecoveryApplicationTicketClaims,
    pub authentication_tag: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryTicketIssueRequest {
    pub recovery_bundle_id: RecoveryBundleId,
    pub selected_item_refs: Vec<String>,
    pub application_kind: RecoveryApplicationKind,
    pub target_worktree_instance_id: WorktreeId,
    pub pre_application_snapshot_id: WorktreeSnapshotId,
}

#[derive(Clone)]
pub struct RecoveryTicketService {
    writer: WriterHandle,
    cas: CasStore,
    key_store: DeviceKeyStore,
    effective_config_hash: [u8; 32],
}

impl RecoveryTicketService {
    pub fn new(
        writer: WriterHandle,
        cas: CasStore,
        key_store: DeviceKeyStore,
        effective_config_hash: [u8; 32],
    ) -> Self {
        Self {
            writer,
            cas,
            key_store,
            effective_config_hash,
        }
    }

    pub async fn issue(
        &self,
        request: RecoveryTicketIssueRequest,
    ) -> Result<RecoveryApplicationTicket, RecoveryError> {
        self.issue_for_application(request, RecoveryApplicationId::new_v7())
            .await
    }

    pub(super) async fn issue_for_application(
        &self,
        request: RecoveryTicketIssueRequest,
        prospective_recovery_application_id: RecoveryApplicationId,
    ) -> Result<RecoveryApplicationTicket, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery = RecoveryCurrentView::from_snapshot(&projected)?;
        let repository = RepositoryCurrentView::from_snapshot(&projected)?;
        let bundle = recovery
            .state
            .bundles
            .get(&request.recovery_bundle_id)
            .ok_or(RecoveryError::StaleCurrent)?;
        let target_snapshot = validate_target(
            bundle,
            &repository,
            request.target_worktree_instance_id,
            request.pre_application_snapshot_id,
            true,
        )?;
        let selected_content_refs = select_content_refs(bundle, &request.selected_item_refs)?;
        validate_kind(request.application_kind, &selected_content_refs)?;
        verify_cas_refs(&self.cas, &selected_content_refs)?;
        let key = self
            .key_store
            .load()
            .map_err(|_| RecoveryError::Protection)?;
        let claims = RecoveryApplicationTicketClaims {
            ticket_version: RECOVERY_APPLICATION_TICKET_VERSION,
            prospective_recovery_application_id,
            recovery_bundle_id: request.recovery_bundle_id,
            selected_content_refs,
            application_kind: request.application_kind,
            target_worktree_instance_id: request.target_worktree_instance_id,
            pre_application_snapshot_id: request.pre_application_snapshot_id,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: RECOVERY_ALGORITHM_REVISION.into(),
            issued_at_us: current_time_us()
                .max(bundle.captured_at_us)
                .max(target_snapshot.captured_at_us),
            device_key_generation: key.generation(),
        };
        validate_claims_shape(&claims)?;
        let authentication_tag = recovery_ticket_auth_tag(&claims.canonical_value(), &key)
            .map_err(|_| RecoveryError::Protection)?;
        Ok(RecoveryApplicationTicket {
            claims,
            authentication_tag,
        })
    }

    pub async fn verify(
        &self,
        ticket: &RecoveryApplicationTicket,
    ) -> Result<RecoveryApplicationTicketClaims, RecoveryError> {
        validate_claims_shape(&ticket.claims)?;
        let key = self
            .key_store
            .load()
            .map_err(|_| RecoveryError::Protection)?;
        if ticket.claims.device_key_generation != key.generation()
            || ticket.claims.effective_config_hash != self.effective_config_hash
            || !verify_recovery_ticket_auth_tag(
                &ticket.claims.canonical_value(),
                &key,
                &ticket.authentication_tag,
            )
            .map_err(|_| RecoveryError::Protection)?
        {
            return Err(RecoveryError::InvalidInput);
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery = RecoveryCurrentView::from_snapshot(&projected)?;
        let repository = RepositoryCurrentView::from_snapshot(&projected)?;
        let bundle = recovery
            .state
            .bundles
            .get(&ticket.claims.recovery_bundle_id)
            .ok_or(RecoveryError::StaleCurrent)?;
        validate_target(
            bundle,
            &repository,
            ticket.claims.target_worktree_instance_id,
            ticket.claims.pre_application_snapshot_id,
            false,
        )?;
        let selected = select_content_refs(
            bundle,
            &ticket
                .claims
                .selected_content_refs
                .iter()
                .map(|value| value.item_ref.clone())
                .collect::<Vec<_>>(),
        )?;
        if selected != ticket.claims.selected_content_refs {
            return Err(RecoveryError::InvalidInput);
        }
        validate_kind(ticket.claims.application_kind, &selected)?;
        verify_cas_refs(&self.cas, &selected)?;
        Ok(ticket.claims.clone())
    }
}

impl RecoveryApplicationTicketClaims {
    fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                "algorithm_revision".into(),
                CanonicalValue::String(self.algorithm_revision.clone()),
            ),
            (
                "application_kind".into(),
                CanonicalValue::String(application_kind_name(self.application_kind).into()),
            ),
            (
                "device_key_generation".into(),
                CanonicalValue::Integer(i128::from(self.device_key_generation)),
            ),
            (
                "effective_config_hash".into(),
                CanonicalValue::Bytes(self.effective_config_hash.to_vec()),
            ),
            (
                "issued_at_us".into(),
                CanonicalValue::Integer(i128::from(self.issued_at_us)),
            ),
            (
                "pre_application_snapshot_id".into(),
                CanonicalValue::String(self.pre_application_snapshot_id.to_string()),
            ),
            (
                "prospective_recovery_application_id".into(),
                CanonicalValue::String(self.prospective_recovery_application_id.to_string()),
            ),
            (
                "recovery_bundle_id".into(),
                CanonicalValue::String(self.recovery_bundle_id.to_string()),
            ),
            (
                "selected_content_refs".into(),
                CanonicalValue::Sequence(
                    self.selected_content_refs
                        .iter()
                        .map(content_ref_value)
                        .collect(),
                ),
            ),
            (
                "target_worktree_instance_id".into(),
                CanonicalValue::String(self.target_worktree_instance_id.to_string()),
            ),
            (
                "ticket_version".into(),
                CanonicalValue::Integer(i128::from(self.ticket_version)),
            ),
        ])
    }
}

fn validate_claims_shape(claims: &RecoveryApplicationTicketClaims) -> Result<(), RecoveryError> {
    if claims.ticket_version != RECOVERY_APPLICATION_TICKET_VERSION
        || claims.issued_at_us < 0
        || claims.device_key_generation == 0
        || claims.effective_config_hash == [0; 32]
        || claims.algorithm_revision != RECOVERY_ALGORITHM_REVISION
        || claims.selected_content_refs.is_empty()
        || !claims.selected_content_refs.iter().all(|value| {
            value
                .validate(value.protected_relative_path.is_some())
                .is_ok()
        })
    {
        return Err(RecoveryError::InvalidInput);
    }
    let mut items = BTreeSet::new();
    if !claims
        .selected_content_refs
        .iter()
        .all(|value| items.insert(&value.item_ref))
    {
        return Err(RecoveryError::InvalidInput);
    }
    Ok(())
}

fn validate_target<'a>(
    bundle: &RecoveryBundle,
    repository: &'a RepositoryCurrentView,
    worktree_id: WorktreeId,
    snapshot_id: WorktreeSnapshotId,
    require_active: bool,
) -> Result<&'a evertrace_domain::repository::WorktreeSnapshot, RecoveryError> {
    let source_worktree = repository
        .worktrees
        .get(&bundle.source_worktree_instance_id)
        .ok_or(RecoveryError::StaleCurrent)?;
    let source_snapshot = repository
        .snapshots
        .get(&bundle.source_snapshot_id)
        .ok_or(RecoveryError::StaleCurrent)?;
    let target_worktree = repository
        .worktrees
        .get(&worktree_id)
        .ok_or(RecoveryError::StaleCurrent)?;
    let target_snapshot = repository
        .snapshots
        .get(&snapshot_id)
        .ok_or(RecoveryError::StaleCurrent)?;
    if source_snapshot.worktree_instance_id != bundle.source_worktree_instance_id
        || target_snapshot.worktree_instance_id != worktree_id
        || source_worktree.repository_instance_id != target_worktree.repository_instance_id
        || (require_active
            && (target_worktree.lifecycle != WorktreeLifecycle::Active
                || target_worktree.current_snapshot_id != Some(snapshot_id)))
    {
        return Err(RecoveryError::InvalidInput);
    }
    Ok(target_snapshot)
}

fn select_content_refs(
    bundle: &RecoveryBundle,
    selected_item_refs: &[String],
) -> Result<Vec<RecoveryContentRef>, RecoveryError> {
    if selected_item_refs.is_empty()
        || selected_item_refs.iter().collect::<BTreeSet<_>>().len() != selected_item_refs.len()
    {
        return Err(RecoveryError::InvalidInput);
    }
    let available = bundle
        .tracked_diff_blob_refs
        .iter()
        .chain(&bundle.tracked_file_blob_refs)
        .chain(&bundle.index_state_refs)
        .chain(&bundle.untracked_file_blob_refs)
        .map(|value| (value.item_ref.as_str(), value))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut selected = selected_item_refs
        .iter()
        .map(|item| {
            available
                .get(item.as_str())
                .cloned()
                .ok_or(RecoveryError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.item_ref.cmp(&right.item_ref));
    Ok(selected)
}

fn validate_kind(
    kind: RecoveryApplicationKind,
    selected: &[RecoveryContentRef],
) -> Result<(), RecoveryError> {
    let categories = selected
        .iter()
        .map(|value| {
            if value.protected_relative_path.is_some() {
                "file"
            } else if value.item_ref == "git:tracked_diff" {
                "patch"
            } else if value.item_ref == "git:index_diff" {
                "index"
            } else {
                "unknown"
            }
        })
        .collect::<BTreeSet<_>>();
    let valid = match kind {
        RecoveryApplicationKind::Patch => categories == BTreeSet::from(["patch"]),
        RecoveryApplicationKind::FileRestore => categories == BTreeSet::from(["file"]),
        RecoveryApplicationKind::IndexRestore => categories == BTreeSet::from(["index"]),
        RecoveryApplicationKind::Mixed => categories.len() > 1 && !categories.contains("unknown"),
    };
    if valid {
        Ok(())
    } else {
        Err(RecoveryError::InvalidInput)
    }
}

fn verify_cas_refs(cas: &CasStore, selected: &[RecoveryContentRef]) -> Result<(), RecoveryError> {
    for content in selected {
        verify_protected_ref(cas, &content.payload)?;
        if let Some(path) = &content.protected_relative_path {
            verify_protected_ref(cas, path)?;
        }
    }
    Ok(())
}

fn verify_protected_ref(
    cas: &CasStore,
    reference: &evertrace_domain::repository::RecoveryProtectedRef,
) -> Result<(), RecoveryError> {
    let digest =
        CasDigest::from_str(&reference.cas_ref).map_err(|_| RecoveryError::InvalidInput)?;
    let bytes = cas.read(&digest).map_err(|_| RecoveryError::InvalidInput)?;
    if u64::try_from(bytes.len()).ok() != Some(reference.protected_length) {
        return Err(RecoveryError::InvalidInput);
    }
    Ok(())
}

fn content_ref_value(value: &RecoveryContentRef) -> CanonicalValue {
    CanonicalValue::Map(vec![
        (
            "item_ref".into(),
            CanonicalValue::String(value.item_ref.clone()),
        ),
        ("payload".into(), protected_ref_value(&value.payload)),
        (
            "protected_relative_path".into(),
            value
                .protected_relative_path
                .as_ref()
                .map_or(CanonicalValue::Null, protected_ref_value),
        ),
    ])
}

fn protected_ref_value(
    value: &evertrace_domain::repository::RecoveryProtectedRef,
) -> CanonicalValue {
    CanonicalValue::Map(vec![
        (
            "cas_ref".into(),
            CanonicalValue::String(value.cas_ref.clone()),
        ),
        (
            "original_length".into(),
            CanonicalValue::Integer(i128::from(value.original_length)),
        ),
        (
            "protected_length".into(),
            CanonicalValue::Integer(i128::from(value.protected_length)),
        ),
        (
            "protected_secret_digest".into(),
            value
                .protected_secret_digest
                .as_ref()
                .map_or(CanonicalValue::Null, |digest| {
                    CanonicalValue::String(digest.clone())
                }),
        ),
        (
            "redaction_spans".into(),
            CanonicalValue::Integer(i128::from(value.redaction_spans)),
        ),
    ])
}

const fn application_kind_name(kind: RecoveryApplicationKind) -> &'static str {
    match kind {
        RecoveryApplicationKind::Patch => "patch",
        RecoveryApplicationKind::FileRestore => "file_restore",
        RecoveryApplicationKind::IndexRestore => "index_restore",
        RecoveryApplicationKind::Mixed => "mixed",
    }
}
