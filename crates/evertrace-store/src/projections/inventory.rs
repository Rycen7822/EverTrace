use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    evidence::{SourceObservation, SourceReceipt},
    ids::{JobId, RepositoryId, SourceObservationId, SourceReceiptId, WorktreeId},
    inventory::{CapabilityInventoryRecorded, InventoryContext},
    repository::{RepositoryCapabilityState, RepositoryInstance, WorktreeInstance},
};

use super::{
    JournalPayload, ObjectFamily, ObjectRow, StoreError, physical_object_row, require_physical_row,
};
use crate::{DurableJob, JobStatus, SourceKind, purge::ScopePurgeState};

pub const INVENTORY_JOB_KIND: &str = "capability_inventory_v1";
pub const INVENTORY_OBJECT_KIND: &str = "capability_inventory";

/// A single current journal frontier, not a permission decision or a partial
/// ProjectionSnapshot. The caller must still verify its current Host report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryCurrentContext {
    pub frontier: u64,
    pub repository: Option<RepositoryInstance>,
    pub worktree: Option<WorktreeInstance>,
    pub latest_completion: Option<CapabilityInventoryRecorded>,
    pub restoration_boundary: Option<CapabilityInventoryRecorded>,
    pub job: Option<DurableJob>,
    pub purge_pending_or_purged: bool,
}

impl InventoryCurrentContext {
    /// Structural currentness only. This does not establish live Host trust,
    /// filesystem currentness, source selection, or permission to read CAS.
    pub fn post_restoration_completion(&self) -> Option<&CapabilityInventoryRecorded> {
        let repository = self.repository.as_ref()?;
        let boundary = self.restoration_boundary.as_ref()?;
        let latest = self.latest_completion.as_ref()?;
        let worktree = self.worktree.as_ref()?;
        (!repository.user_disabled
            && !self.purge_pending_or_purged
            && repository
                .capability_state
                .as_ref()
                .is_some_and(|state| !state.trust_revoked)
            && latest.repository_revision >= boundary.repository_revision
            && latest.repository_revision <= repository.repository_revision
            && latest.context.repository_id == repository.repository_id
            && worktree.repository_instance_id == repository.repository_id
            && worktree.worktree_instance_id == latest.context.worktree_id
            && worktree.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active
            && worktree.path_history.last().is_some_and(|path| {
                path.first_observed_at_us <= latest.recorded_at_us
                    && worktree.current_path.as_ref() == Some(&path.path)
            })
            && worktree
                .current_path
                .as_ref()
                .is_some_and(|path| std::path::Path::new(&latest.context.cwd).starts_with(path)))
        .then_some(latest)
    }
}

pub fn inventory_repository_target(repository: RepositoryId, revision: u32) -> String {
    format!("{repository}@{revision}")
}

pub fn inventory_job_worktree(job: &DurableJob) -> Option<WorktreeId> {
    let mut parts = job.idempotency_key.split('|');
    let intent = parts.next()?;
    let worktree = parts.next()?;
    let context = parts.next()?;
    if !intent.starts_with("capability_inventory:scan:")
        && !intent.starts_with("capability_inventory:enable:")
    {
        return None;
    }
    if parts.next().is_some()
        || !matches!(context, "new" | "root") && context.parse::<JobId>().is_err()
    {
        return None;
    }
    worktree.parse().ok()
}

pub fn inventory_job_context_ref(job: &DurableJob) -> Option<&str> {
    inventory_job_worktree(job)?;
    job.idempotency_key
        .rsplit_once('|')
        .map(|(_, context)| context)
}

pub(super) fn job_repository(job: &DurableJob) -> Option<RepositoryId> {
    if job.kind != INVENTORY_JOB_KIND {
        return None;
    }
    let (repository, revision) = job.target_revision.rsplit_once('@')?;
    let repository = repository.parse::<RepositoryId>().ok()?;
    let revision = revision.parse::<u32>().ok()?;
    (revision != 0 && inventory_repository_target(repository, revision) == job.target_revision)
        .then_some(repository)
}

pub(super) struct InventoryAdmission<'a> {
    pub inventory: &'a InventoryState,
    pub repositories: &'a BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    pub jobs: &'a BTreeMap<JobId, DurableJob>,
    pub purges: &'a ScopePurgeState,
    pub source_receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub source_observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
}

impl InventoryAdmission<'_> {
    pub(super) fn validate_procedure_coverage<'a>(
        &self,
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
        require_refs: bool,
        error: StoreError,
    ) -> Result<(), StoreError> {
        use evertrace_domain::semantic::{AcceptedProposalTarget, ProposalPayload};
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        for payload in &payloads {
            let JournalPayload::RevisionProposalRecorded(proposal) = payload else {
                continue;
            };
            let Some(AcceptedProposalTarget::Procedure {
                auto_full_audit: Some(audit),
                ..
            }) = proposal
                .acceptance
                .as_ref()
                .map(|value| &value.accepted_target)
            else {
                continue;
            };
            let Some(refs) = &audit.capability_inventory_refs else {
                if require_refs {
                    return Err(error);
                }
                continue; // Original absent bytes retain their historical interpretation.
            };
            let ProposalPayload::Procedure(procedure) = &proposal.payload else {
                return Err(error);
            };
            self.validate_procedure_inventory_refs(
                procedure.draft().scope,
                &proposal.source_cohort_refs,
                refs,
                &payloads,
                error,
            )?;
        }
        Ok(())
    }

    fn validate_procedure_inventory_refs(
        &self,
        procedure_scope: evertrace_domain::procedure::ProcedureScope,
        source_refs: &[String],
        refs: &[JobId],
        payloads: &[&JournalPayload],
        error: StoreError,
    ) -> Result<(), StoreError> {
        for reference in refs {
            let (fact, fact_seq) = self.inventory.completed.get(reference).ok_or(error)?;
            let current = self.inventory.latest(&fact.context).ok_or(error)?;
            if !refs.contains(&current.job_id) {
                return Err(error);
            }
            if current.job_id != *reference
                && !source_refs.iter().any(|source| {
                    let receipt = source
                        .parse::<SourceReceiptId>()
                        .ok()
                        .and_then(|id| self.source_receipts.get(&id))
                        .or_else(|| {
                            source
                                .parse::<SourceObservationId>()
                                .ok()
                                .and_then(|id| self.source_observations.get(&id))
                                .and_then(|(observation, _)| {
                                    self.source_receipts.get(&observation.source_receipt_ref)
                                })
                        });
                    receipt.is_some_and(|(receipt, seq)| {
                        receipt.repository_instance_id == Some(fact.context.repository_id)
                            && receipt.worktree_instance_id == Some(fact.context.worktree_id)
                            && fact
                                .evidence_refs
                                .contains(&format!("session:{}", receipt.source_session_ref))
                            && fact_seq <= seq
                            && fact.recorded_at_us
                                <= receipt.event_time_us.min(receipt.recorded_at_us)
                    })
                })
            {
                return Err(error);
            }
            let (old, _) = self
                .repositories
                .get(&fact.context.repository_id)
                .ok_or(error)?;
            let repository = payloads
                .iter()
                .find_map(|payload| match payload {
                    JournalPayload::RepositoryInstanceRecorded(value)
                        if value.repository_id == old.repository_id =>
                    {
                        Some(value.as_ref())
                    }
                    _ => None,
                })
                .unwrap_or(old);
            let boundary = repository
                .capability_state
                .as_ref()
                .and_then(|state| state.revalidated_inventory_ref)
                .and_then(|id| self.inventory.completed.get(&id))
                .ok_or(error)?;
            let scope = evertrace_domain::procedure::ProcedureScope::Worktree {
                repository_id: fact.context.repository_id,
                worktree_id: fact.context.worktree_id,
            };
            if repository.user_disabled
                || repository
                    .capability_state
                    .as_ref()
                    .is_none_or(|state| state.trust_revoked)
                || self.purges.current(repository.repository_id).is_some()
                || payloads.iter().any(|payload| {
                    matches!(payload, JournalPayload::ScopePurgeProgressRecorded(value)
                        if value.target.repository_id() == repository.repository_id)
                })
                || current.repository_revision < boundary.0.repository_revision
                || current.repository_revision > repository.repository_revision
                || fact.repository_revision > repository.repository_revision
                || !procedure_scope.contains(&scope)
                || self
                    .worktrees
                    .get(&fact.context.worktree_id)
                    .is_none_or(|(worktree, _)| worktree.lifecycle.is_terminal())
            {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn validate<'a>(
        &self,
        payloads: impl IntoIterator<Item = (&'a JournalPayload, SourceKind, i64)>,
        error: StoreError,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let mut completed = BTreeMap::new();
        for (payload, source, at) in &payloads {
            let JournalPayload::CapabilityInventoryRecorded(fact) = payload else {
                continue;
            };
            let repository = self
                .repositories
                .get(&fact.context.repository_id)
                .ok_or(error)?
                .0
                .clone();
            let worktree = &self
                .worktrees
                .get(&fact.context.worktree_id)
                .ok_or(error)?
                .0;
            let job = self.jobs.get(&fact.job_id).ok_or(error)?;
            let terminal = payloads
                .iter()
                .find_map(|(payload, _, _)| match payload {
                    JournalPayload::JobState(next) if next.job_id == fact.job_id => Some(next),
                    _ => None,
                })
                .ok_or(error)?;
            let successor = payloads.iter().find_map(|(payload, _, _)| match payload {
                JournalPayload::RepositoryInstanceRecorded(next)
                    if next.repository_id == repository.repository_id =>
                {
                    Some(next.as_ref())
                }
                _ => None,
            });
            let final_repository = successor.unwrap_or(&repository);
            let context_matches = match inventory_job_context_ref(job) {
                Some("new") => job
                    .idempotency_key
                    .starts_with("capability_inventory:scan:"),
                Some("root") => worktree.current_path.as_deref() == Some(fact.context.cwd.as_str()),
                Some(reference) => reference
                    .parse::<JobId>()
                    .ok()
                    .and_then(|id| self.inventory.completed.get(&id))
                    .is_some_and(|(old, _)| old.context == fact.context),
                None => false,
            };
            if *source != SourceKind::System
                || !context_matches
                || fact.recorded_at_us != *at
                || job.kind != INVENTORY_JOB_KIND
                || job.model_id.is_some()
                || inventory_job_worktree(job) != Some(fact.context.worktree_id)
                || job.state != JobStatus::Leased
                || job.lease_until_us.is_none_or(|until| until <= *at)
                || job.target_revision
                    != inventory_repository_target(
                        repository.repository_id,
                        repository.repository_revision,
                    )
                || terminal.state != JobStatus::Succeeded
                || terminal
                    .terminal
                    .as_ref()
                    .and_then(|audit| audit.result_ref.as_deref())
                    != Some(fact.job_id.to_string().as_str())
                || self.purges.current(repository.repository_id).is_some()
                || self.inventory.completed.contains_key(&fact.job_id)
                || completed.insert(fact.job_id, fact.as_ref()).is_some()
                || worktree.repository_instance_id != repository.repository_id
                || worktree.lifecycle.is_terminal()
                || worktree
                    .current_path
                    .as_ref()
                    .is_none_or(|root| !std::path::Path::new(&fact.context.cwd).starts_with(root))
                || final_repository.repository_revision != fact.repository_revision
                || final_repository.user_disabled
                || final_repository
                    .capability_state
                    .as_ref()
                    .is_none_or(|state| {
                        state.trust_revoked || state.revalidated_inventory_ref.is_none()
                    })
            {
                return Err(error);
            }
            let blocked = repository.user_disabled
                || repository
                    .capability_state
                    .as_ref()
                    .is_some_and(|state| state.trust_revoked);
            if blocked
                && !job
                    .idempotency_key
                    .starts_with("capability_inventory:enable:")
            {
                return Err(error);
            }
            if repository
                .capability_state
                .as_ref()
                .and_then(|state| state.revalidated_inventory_ref)
                .is_some()
                && final_repository.capability_state != repository.capability_state
                && !job
                    .idempotency_key
                    .starts_with("capability_inventory:enable:")
            {
                return Err(error);
            }
        }
        for (payload, source, _) in &payloads {
            let JournalPayload::RepositoryInstanceRecorded(next) = payload else {
                continue;
            };
            let Some((previous, _)) = self.repositories.get(&next.repository_id) else {
                if next.user_disabled || next.capability_state.is_some() {
                    return Err(error);
                }
                continue;
            };
            if previous.user_disabled == next.user_disabled
                && previous.capability_state == next.capability_state
            {
                continue;
            }
            let restored = next
                .capability_state
                .as_ref()
                .and_then(|state| state.revalidated_inventory_ref)
                .and_then(|id| completed.get(&id))
                .is_some_and(|fact| {
                    fact.context.repository_id == next.repository_id
                        && fact.repository_revision == next.repository_revision
                });
            let mut expected = previous.clone();
            expected.repository_revision = next.repository_revision;
            expected.predecessor_revision = next.predecessor_revision;
            expected.recorded_at_us = next.recorded_at_us;
            if restored && *source == SourceKind::System {
                expected.user_disabled = false;
                expected.capability_state = next.capability_state.clone();
            } else if *source == SourceKind::Manual && next.user_disabled {
                expected.user_disabled = true;
            } else if *source == SourceKind::System
                && next
                    .capability_state
                    .as_ref()
                    .is_some_and(|state| state.trust_revoked)
            {
                let state = expected
                    .capability_state
                    .get_or_insert(RepositoryCapabilityState {
                        trust_revoked: false,
                        revalidated_inventory_ref: None,
                    });
                state.trust_revoked = true;
            } else {
                return Err(error);
            }
            if expected != **next {
                return Err(error);
            }
        }
        for (payload, source, _) in &payloads {
            if let JournalPayload::JobState(job) = payload
                && job.kind == INVENTORY_JOB_KIND
            {
                if job_repository(job).is_none() || inventory_job_worktree(job).is_none() {
                    return Err(error);
                }
                if job.state == JobStatus::Succeeded && !completed.contains_key(&job.job_id) {
                    // A successful ordinary rescan may retain an identical
                    // previously completed snapshot. It never restores a gate.
                    let previous = job
                        .terminal
                        .as_ref()
                        .and_then(|audit| audit.result_ref.as_ref())
                        .and_then(|reference| reference.parse::<JobId>().ok())
                        .and_then(|id| self.inventory.completed.get(&id))
                        .map(|(fact, _)| fact);
                    let valid = previous.is_some_and(|fact| {
                        let repository = self
                            .repositories
                            .get(&fact.context.repository_id)
                            .map(|(repository, _)| repository);
                        *source == SourceKind::System
                            && job
                                .idempotency_key
                                .starts_with("capability_inventory:scan:")
                            && inventory_job_worktree(job) == Some(fact.context.worktree_id)
                            && inventory_job_context_ref(job)
                                == Some(fact.job_id.to_string().as_str())
                            && self.inventory.latest(&fact.context) == Some(fact)
                            && repository.is_some_and(|repository| {
                                !repository.user_disabled
                                    && self.purges.current(repository.repository_id).is_none()
                                    && job.target_revision
                                        == inventory_repository_target(
                                            repository.repository_id,
                                            repository.repository_revision,
                                        )
                                    && repository.capability_state.as_ref().is_some_and(|state| {
                                        !state.trust_revoked
                                            && state
                                                .revalidated_inventory_ref
                                                .and_then(|id| self.inventory.completed.get(&id))
                                                .is_some_and(|(boundary, _)| {
                                                    fact.repository_revision
                                                        >= boundary.repository_revision
                                                })
                                    })
                            })
                    });
                    if !valid {
                        return Err(error);
                    }
                }
                if !self.jobs.contains_key(&job.job_id)
                    && job
                        .idempotency_key
                        .starts_with("capability_inventory:enable:")
                    && *source != SourceKind::Manual
                {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct InventoryState {
    pub(super) completed: BTreeMap<JobId, (CapabilityInventoryRecorded, u64)>,
    current: BTreeMap<InventoryContext, JobId>,
}

/// Exact-frontier permission facts for only the repositories a request reads.
/// No inventory body, receipt history, or extra repository cache is copied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryReadContext {
    pub frontier: u64,
    pub repositories: BTreeMap<RepositoryId, RepositoryInstance>,
    pub purged: BTreeSet<RepositoryId>,
}

impl InventoryState {
    pub(super) fn proposal_depends_on_repository(
        &self,
        proposal: &evertrace_domain::semantic::RevisionProposal,
        repository: RepositoryId,
    ) -> bool {
        procedure_inventory_refs(proposal).iter().any(|id| {
            self.completed
                .get(id)
                .is_some_and(|(fact, _)| fact.context.repository_id == repository)
        })
    }

    pub(super) fn validate_procedure_refs<'a>(
        &self,
        proposals: impl Iterator<Item = &'a evertrace_domain::semantic::RevisionProposal>,
    ) -> Result<(), StoreError> {
        for proposal in proposals {
            for reference in procedure_inventory_refs(proposal) {
                let (fact, _) = self
                    .completed
                    .get(reference)
                    .ok_or(StoreError::StoreCorrupt)?;
                let evertrace_domain::semantic::ProposalPayload::Procedure(payload) =
                    &proposal.payload
                else {
                    return Err(StoreError::StoreCorrupt);
                };
                if !payload.draft().scope.contains(
                    &evertrace_domain::procedure::ProcedureScope::Worktree {
                        repository_id: fact.context.repository_id,
                        worktree_id: fact.context.worktree_id,
                    },
                ) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        Ok(())
    }

    pub(super) fn latest(
        &self,
        context: &InventoryContext,
    ) -> Option<&CapabilityInventoryRecorded> {
        self.current
            .get(context)
            .and_then(|id| self.completed.get(id))
            .map(|(fact, _)| fact)
    }

    pub(super) fn validate_relations(
        &self,
        repositories: &BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
        worktrees: &BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    ) -> Result<(), StoreError> {
        for (fact, _) in self.completed.values() {
            if repositories
                .get(&fact.context.repository_id)
                .is_none_or(|(repository, _)| {
                    repository.repository_revision < fact.repository_revision
                })
                || worktrees
                    .get(&fact.context.worktree_id)
                    .is_none_or(|(worktree, _)| {
                        worktree.repository_instance_id != fact.context.repository_id
                    })
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (repository, _) in repositories.values() {
            if let Some(id) = repository
                .capability_state
                .as_ref()
                .and_then(|state| state.revalidated_inventory_ref)
                && self
                    .completed
                    .get(&id)
                    .is_none_or(|(fact, _)| fact.context.repository_id != repository.repository_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(())
    }

    pub(super) fn cas_refs(
        &self,
        repository: RepositoryId,
        matching: bool,
    ) -> impl Iterator<Item = &String> {
        self.completed
            .values()
            .filter(move |(fact, _)| (fact.context.repository_id == repository) == matching)
            .flat_map(|(fact, _)| {
                std::iter::once(&fact.snapshot_cas_ref).chain(&fact.dependency_cas_refs)
            })
    }

    pub(super) fn record(
        &mut self,
        value: CapabilityInventoryRecorded,
        seq: u64,
    ) -> Result<(), StoreError> {
        value.validate().map_err(|_| StoreError::StoreCorrupt)?;
        if self.completed.contains_key(&value.job_id) {
            return Err(StoreError::StoreCorrupt);
        }
        if self.current.get(&value.context).is_none_or(|id| {
            self.completed
                .get(id)
                .is_some_and(|(_, previous)| *previous < seq)
        }) {
            self.current.insert(value.context.clone(), value.job_id);
        }
        self.completed.insert(value.job_id, (value, seq));
        Ok(())
    }

    pub(super) fn restore(
        &mut self,
        value: CapabilityInventoryRecorded,
        row: &ObjectRow,
    ) -> Result<(), StoreError> {
        require_physical_row(
            row,
            ObjectFamily::Evidence,
            INVENTORY_OBJECT_KIND,
            &value.job_id.to_string(),
            &value.job_id.to_string(),
        )?;
        self.record(value, row.source_event_seq)
    }

    pub(super) fn rows(self) -> Result<Vec<ObjectRow>, StoreError> {
        self.completed
            .into_values()
            .map(|(value, seq)| {
                physical_object_row(
                    ObjectFamily::Evidence,
                    INVENTORY_OBJECT_KIND,
                    value.job_id.to_string(),
                    value.job_id.to_string(),
                    &JournalPayload::CapabilityInventoryRecorded(Box::new(value)),
                    seq,
                )
            })
            .collect()
    }
}

fn procedure_inventory_refs(proposal: &evertrace_domain::semantic::RevisionProposal) -> &[JobId] {
    match proposal
        .acceptance
        .as_ref()
        .map(|value| &value.accepted_target)
    {
        Some(evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
            auto_full_audit: Some(audit),
            ..
        }) => audit.capability_inventory_refs.as_deref().unwrap_or(&[]),
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::super::{JournalAdmissionState, ReducerState, reduce_journal};
    use super::*;
    use crate::{
        JobBudget, JobLease, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason,
        JournalCommand, JournalEventDraft, command::prepare_command, journal::rows_for_append,
    };
    use evertrace_domain::{
        ids::CommandId,
        inventory::CapabilityInventoryProfile,
        repository::{GitRegistrationState, PathObservation, WorktreeKind, WorktreeLifecycle},
    };

    fn old_repository() -> serde_json::Value {
        serde_json::json!({
            "repository_id": "repo:01890f47-6a4a-7cc1-98b9-01890f476a01",
            "repository_revision": 1, "predecessor_revision": null,
            "current_path": "/repo", "path_history": [{
                "path": "/repo", "first_observed_at_us": 1,
                "last_observed_at_us": 1, "evidence_refs": ["probe-a"]
            }],
            "git_common_dir_path": "/repo/.git",
            "common_dir_filesystem": { "device": 1, "inode": 2 },
            "object_format": "sha1", "remote_fingerprints": [],
            "derived_from": null, "identity_evidence_refs": ["probe-a"],
            "recorded_at_us": 1
        })
    }

    fn command(payloads: Vec<JournalPayload>, at: i64) -> JournalCommand {
        JournalCommand::new(
            CommandId::new_v7(),
            payloads
                .into_iter()
                .map(|payload| JournalEventDraft::runtime(at, [0; 32], "inventory-v1", payload))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn inventory_old_repository_canonical_is_unchanged() {
        let old = old_repository();
        let repository: RepositoryInstance = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(repository.validate(), Ok(()));
        assert!(!repository.user_disabled);
        assert_eq!(repository.capability_state, None);
        assert_eq!(serde_json::to_value(&repository).unwrap(), old);
        let payload = JournalPayload::RepositoryInstanceRecorded(Box::new(repository));
        let json = payload.canonical_json().unwrap();
        assert!(!json.contains("user_disabled"));
        assert!(!json.contains("capability_state"));
        assert_eq!(
            serde_json::from_str::<JournalPayload>(&json)
                .unwrap()
                .canonical_json()
                .unwrap(),
            json
        );
    }

    #[tokio::test]
    async fn inventory_completion_is_atomic_replayable_and_retains_cas_closure() {
        let repository_command = |value: RepositoryInstance, source: SourceKind, at| {
            let mut event = JournalEventDraft::runtime(
                at,
                [0; 32],
                "inventory-v1",
                JournalPayload::RepositoryInstanceRecorded(Box::new(value)),
            );
            event.source_kind = source;
            JournalCommand::new(CommandId::new_v7(), vec![event]).unwrap()
        };
        let repository: RepositoryInstance = serde_json::from_value(old_repository()).unwrap();
        let worktree = WorktreeInstance {
            worktree_instance_id: WorktreeId::new_v7(),
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository.repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some("/repo".into()),
            path_history: repository.path_history.clone(),
            git_admin_path_history: vec![PathObservation {
                path: "/repo/.git".into(),
                ..repository.path_history[0].clone()
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: None,
            created_event_ref: "probe-a".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        };
        let mut job = DurableJob {
            job_id: JobId::new_v7(),
            idempotency_key: format!(
                "capability_inventory:scan:context-a|{}|new",
                worktree.worktree_instance_id
            ),
            target_revision: inventory_repository_target(repository.repository_id, 1),
            target_watermark: 0,
            target_generation: 1,
            kind: INVENTORY_JOB_KIND.into(),
            algorithm_revision: "inventory-v1".into(),
            model_id: None,
            priority: 0,
            state: JobStatus::Queued,
            attempt: 1,
            backoff_until_us: None,
            config_hash: [0; 32],
            budget: JobBudget {
                max_items: 8,
                max_bytes: Some(4096),
                max_input_tokens: None,
                max_output_tokens: None,
                max_calls: None,
                max_wall_time_ms: 250,
            },
            terminal: None,
            lease_until_us: None,
        };
        let initial = command(
            vec![
                JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
                JournalPayload::WorktreeInstanceRecorded(Box::new(worktree.clone())),
                JournalPayload::JobState(job.clone()),
            ],
            1,
        );
        let mut state = JournalAdmissionState::default()
            .apply_command(&initial, 1)
            .unwrap();
        let lease = command(
            vec![JournalPayload::JobLease(JobLease {
                job_id: job.job_id,
                target_generation: 1,
                attempt: 2,
                lease_until_us: 100,
            })],
            2,
        );
        state = state.apply_command(&lease, 4).unwrap();
        job.state = JobStatus::Succeeded;
        job.attempt = 2;
        job.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Succeeded,
            reason: JobTerminalReason::Completed,
            result_ref: Some(job.job_id.to_string()),
        }));
        let mut successor = repository.clone();
        successor.repository_revision = 2;
        successor.predecessor_revision = Some(1);
        successor.recorded_at_us = 3;
        successor.capability_state = Some(RepositoryCapabilityState {
            trust_revoked: false,
            revalidated_inventory_ref: Some(job.job_id),
        });
        let fact = CapabilityInventoryRecorded {
            job_id: job.job_id,
            context: InventoryContext {
                repository_id: repository.repository_id,
                worktree_id: worktree.worktree_instance_id,
                cwd: "/repo".into(),
                adapter_manifest_id: "d".repeat(64),
                profile: CapabilityInventoryProfile::NativeFiniteAssetsV1,
                host_home: "/home/test".into(),
                host_config_root: "/config/test".into(),
                host_profile: None,
            },
            repository_revision: 2,
            snapshot_cas_ref: "a".repeat(64),
            dependency_cas_refs: vec!["b".repeat(64)],
            evidence_refs: vec!["probe-a".into(), "session:bounded".into()],
            recorded_at_us: 3,
        };
        let completion = command(
            vec![
                JournalPayload::CapabilityInventoryRecorded(Box::new(fact.clone())),
                JournalPayload::RepositoryInstanceRecorded(Box::new(successor)),
                JournalPayload::JobState(job),
            ],
            3,
        );
        let mut missing_fact = completion.events().to_vec();
        missing_fact.remove(0);
        assert!(
            state
                .apply_command(
                    &JournalCommand::new(CommandId::new_v7(), missing_fact).unwrap(),
                    5
                )
                .is_err()
        );
        let mut concurrently_disabled = repository.clone();
        concurrently_disabled.repository_revision = 2;
        concurrently_disabled.predecessor_revision = Some(1);
        concurrently_disabled.recorded_at_us = 3;
        concurrently_disabled.user_disabled = true;
        let closed = state
            .apply_command(
                &repository_command(concurrently_disabled, SourceKind::Manual, 3),
                5,
            )
            .unwrap();
        assert!(
            closed.apply_command(&completion, 6).is_err(),
            "an in-flight completion must not clear a concurrent user disable"
        );
        let committed = state.apply_command(&completion, 5).unwrap();
        assert_eq!(committed.inventory.completed[&fact.job_id].0, fact);
        let mut rows = Vec::new();
        for command in [&initial, &lease, &completion] {
            rows.extend(
                rows_for_append(&prepare_command(command).unwrap(), rows.len() as u64 + 1, 0)
                    .unwrap(),
            );
        }
        let full = reduce_journal(&rows).unwrap();
        assert_eq!(
            full.live_cas_refs().unwrap(),
            ["a".repeat(64), "b".repeat(64)].into_iter().collect()
        );
        let restored = ReducerState::from_current_rows(&full.rows, full.frontier).unwrap();
        assert_eq!(restored.inventory.completed[&fact.job_id].0, fact);
        let directory = tempfile::tempdir().unwrap();
        let data_root = directory.path().join("data");
        let mut writer = crate::JournalWriter::open(&data_root).await.unwrap();
        for command in [&initial, &lease, &completion] {
            writer.commit(command, 10).await.unwrap();
        }
        let actual = writer.project().await.unwrap();
        let exact = writer
            .inventory_context(&fact.context, Some(fact.job_id))
            .unwrap();
        assert_eq!(exact.frontier, writer.frontier());
        assert_eq!(exact.post_restoration_completion(), Some(&fact));
        assert_eq!(
            actual.live_cas_refs().unwrap(),
            full.live_cas_refs().unwrap()
        );
        let before_retry = writer.frontier();
        assert!(writer.commit(&completion, 11).await.unwrap().replayed);
        assert_eq!(writer.frontier(), before_retry);
        drop(writer);
        let mut writer = crate::JournalWriter::open(&data_root).await.unwrap();
        assert!(writer.commit(&completion, 12).await.unwrap().replayed);
        assert_eq!(writer.frontier(), before_retry);
        assert_eq!(writer.project().await.unwrap(), actual);
        assert_eq!(writer.full_projection().await.unwrap(), actual);
        let replayed = JournalAdmissionState::from_journal_rows(&rows).unwrap();
        assert_eq!(
            replayed.inventory.completed[&fact.job_id],
            committed.inventory.completed[&fact.job_id]
        );
        assert!(committed.apply_command(&completion, 8).is_err());
        let mut job_b = committed.jobs[&fact.job_id].clone();
        job_b.job_id = JobId::new_v7();
        job_b.idempotency_key = format!(
            "capability_inventory:scan:context-b|{}|new",
            worktree.worktree_instance_id
        );
        job_b.target_revision = inventory_repository_target(repository.repository_id, 2);
        job_b.state = JobStatus::Queued;
        job_b.attempt = 1;
        job_b.terminal = None;
        let mut with_b = committed
            .apply_command(
                &command(vec![JournalPayload::JobState(job_b.clone())], 4),
                8,
            )
            .unwrap();
        with_b = with_b
            .apply_command(
                &command(
                    vec![JournalPayload::JobLease(JobLease {
                        job_id: job_b.job_id,
                        target_generation: 1,
                        attempt: 2,
                        lease_until_us: 100,
                    })],
                    5,
                ),
                9,
            )
            .unwrap();
        let mut fact_b = fact.clone();
        fact_b.job_id = job_b.job_id;
        fact_b.context.cwd = "/repo/b".into();
        fact_b.snapshot_cas_ref = "c".repeat(64);
        fact_b.recorded_at_us = 6;
        job_b.state = JobStatus::Succeeded;
        job_b.attempt = 2;
        job_b.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Succeeded,
            reason: JobTerminalReason::Completed,
            result_ref: Some(job_b.job_id.to_string()),
        }));
        with_b = with_b
            .apply_command(
                &command(
                    vec![
                        JournalPayload::CapabilityInventoryRecorded(Box::new(fact_b.clone())),
                        JournalPayload::JobState(job_b),
                    ],
                    6,
                ),
                10,
            )
            .unwrap();
        let context_a = with_b.inventory_context(&fact.context, None).unwrap();
        let context_b = with_b.inventory_context(&fact_b.context, None).unwrap();
        assert_eq!(context_a.post_restoration_completion(), Some(&fact));
        assert_eq!(context_b.post_restoration_completion(), Some(&fact_b));
        // Reuse the admitted completion chain for a newer snapshot of A.
        // History remains readable only alongside this actual current ref.
        let mut job_c = with_b.jobs[&fact_b.job_id].clone();
        job_c.job_id = JobId::new_v7();
        job_c.idempotency_key = format!(
            "capability_inventory:scan:history|{}|new",
            worktree.worktree_instance_id
        );
        job_c.state = JobStatus::Queued;
        job_c.attempt = 1;
        job_c.terminal = None;
        let mut with_history = with_b
            .apply_command(
                &command(vec![JournalPayload::JobState(job_c.clone())], 7),
                12,
            )
            .unwrap();
        with_history = with_history
            .apply_command(
                &command(
                    vec![JournalPayload::JobLease(JobLease {
                        job_id: job_c.job_id,
                        target_generation: 1,
                        attempt: 2,
                        lease_until_us: 100,
                    })],
                    8,
                ),
                13,
            )
            .unwrap();
        let mut fact_c = fact.clone();
        fact_c.job_id = job_c.job_id;
        fact_c.snapshot_cas_ref = "e".repeat(64);
        fact_c.recorded_at_us = 9;
        job_c.state = JobStatus::Succeeded;
        job_c.attempt = 2;
        job_c.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Succeeded,
            reason: JobTerminalReason::Completed,
            result_ref: Some(job_c.job_id.to_string()),
        }));
        with_history = with_history
            .apply_command(
                &command(
                    vec![
                        JournalPayload::CapabilityInventoryRecorded(Box::new(fact_c.clone())),
                        JournalPayload::JobState(job_c),
                    ],
                    9,
                ),
                14,
            )
            .unwrap();
        use evertrace_domain::evidence::{
            SourceInstanceId, SourceRecordIdentity, SourceRevision, source_observation_id,
            source_receipt_id,
        };
        let instance = SourceInstanceId::parse("inventory-source").unwrap();
        let revision = SourceRevision::parse("revision-1").unwrap();
        let record = SourceRecordIdentity::parse("record-1").unwrap();
        let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
        let receipt: SourceReceipt = serde_json::from_value(serde_json::json!({
            "source_receipt_id": receipt_id,
            "source_observation_id": source_observation_id(&instance, &revision, &record).unwrap(),
            "source_instance_id": instance, "source_kind": "codex_session_jsonl",
            "identity_domain": "codex-session-v1", "source_ref": "source", "source_session_ref": "bounded",
            "source_revision": revision, "source_record_identity": record, "identity_strength": "stable_native",
            "source_sequence": 1, "task_id": null,
            "repository_instance_id": repository.repository_id, "worktree_instance_id": worktree.worktree_instance_id,
            "source_byte_range": null, "spool_byte_range": {"start": 0, "end": 1},
            "source_revision_mode": "append", "previous_source_revision": null, "close_watermark": 1,
            "observation_role": "message", "unsupported_record_classification": null,
            "capture_completeness": "complete", "archive_mode": "exact", "cas_ref": "f".repeat(64),
            "protected_length": 1, "original_length": 1, "protected_secret_digest": null, "redaction_spans": [],
            "adapter_revision": 1, "adapter_manifest_ref": "inventory-test", "eligible_event_manifest_ref": "inventory-test",
            "parser_revision": 1, "canonicalization_revision": 1, "detector_revision": 1, "redaction_revision": 1,
            "protection_key_generation": 1, "event_time_us": 4, "recorded_at_us": 4
        })).unwrap();
        receipt.validate().unwrap();
        let source_seq = with_history.inventory.completed[&fact.job_id].1 + 1;
        with_history
            .source_receipts
            .insert(receipt_id, (receipt.clone(), source_seq));
        let scope = evertrace_domain::procedure::ProcedureScope::Repository {
            repository_id: repository.repository_id,
        };
        let source_refs = vec![receipt_id.to_string()];
        let inventory_refs = vec![fact.job_id, fact_c.job_id];
        let validate = |state: &JournalAdmissionState, refs: &[JobId]| {
            state
                .inventory_admission()
                .validate_procedure_inventory_refs(
                    scope,
                    &source_refs,
                    refs,
                    &[],
                    StoreError::InvalidInput,
                )
        };
        assert!(validate(&with_history, &inventory_refs).is_ok());
        assert!(validate(&with_history, &[fact.job_id]).is_err());
        assert!(validate(&with_history, &[fact_c.job_id]).is_ok());
        let mut future = with_history.clone();
        future.source_receipts.get_mut(&receipt_id).unwrap().1 = source_seq - 2;
        assert!(validate(&future, &inventory_refs).is_err());
        let mut late_import = with_history.clone();
        late_import
            .source_receipts
            .get_mut(&receipt_id)
            .unwrap()
            .0
            .event_time_us = 2;
        assert!(
            validate(&late_import, &inventory_refs).is_err(),
            "later ingestion cannot backfill an installation into the source's original time"
        );
        let mut wrong_source = with_history.clone();
        wrong_source
            .source_receipts
            .get_mut(&receipt_id)
            .unwrap()
            .0
            .source_session_ref = "other".into();
        assert!(validate(&wrong_source, &inventory_refs).is_err());
        wrong_source.source_receipts.get_mut(&receipt_id).unwrap().0 = receipt;
        wrong_source
            .source_receipts
            .get_mut(&receipt_id)
            .unwrap()
            .0
            .worktree_instance_id = Some(WorktreeId::new_v7());
        assert!(validate(&wrong_source, &inventory_refs).is_err());
        let mut disabled = with_history.repositories[&repository.repository_id]
            .0
            .clone();
        disabled.repository_revision += 1;
        disabled.predecessor_revision = Some(disabled.repository_revision - 1);
        disabled.recorded_at_us = 10;
        disabled.user_disabled = true;
        let disabled = with_history
            .apply_command(&repository_command(disabled, SourceKind::Manual, 10), 16)
            .unwrap();
        assert!(validate(&disabled, &inventory_refs).is_err());
        let mut changed_worktree = worktree.clone();
        changed_worktree.worktree_revision = 2;
        changed_worktree.predecessor_revision = Some(1);
        changed_worktree.recorded_at_us = 7;
        // A compatible new revision preserves both exact-context completions.
        let compatible = with_b
            .apply_command(
                &command(
                    vec![JournalPayload::WorktreeInstanceRecorded(Box::new(
                        changed_worktree.clone(),
                    ))],
                    7,
                ),
                12,
            )
            .unwrap();
        assert!(
            compatible
                .inventory_context(&fact.context, None)
                .unwrap()
                .post_restoration_completion()
                .is_some()
        );
        changed_worktree.worktree_revision = 3;
        changed_worktree.predecessor_revision = Some(2);
        changed_worktree.recorded_at_us = 8;
        changed_worktree.lifecycle = WorktreeLifecycle::Missing;
        let missing = compatible
            .apply_command(
                &command(
                    vec![JournalPayload::WorktreeInstanceRecorded(Box::new(
                        changed_worktree.clone(),
                    ))],
                    8,
                ),
                13,
            )
            .unwrap();
        let current = missing.inventory_context(&fact.context, None).unwrap();
        assert!(current.post_restoration_completion().is_none());
        assert_eq!(current.latest_completion, Some(fact.clone()));
        changed_worktree.worktree_revision = 4;
        changed_worktree.predecessor_revision = Some(3);
        changed_worktree.recorded_at_us = 9;
        changed_worktree.lifecycle = WorktreeLifecycle::Active;
        changed_worktree.current_path = Some("/".into());
        changed_worktree.path_history.push(PathObservation {
            path: "/".into(),
            first_observed_at_us: 9,
            last_observed_at_us: 9,
            evidence_refs: vec!["move-observation".into()],
        });
        let moved = missing
            .apply_command(
                &command(
                    vec![JournalPayload::WorktreeInstanceRecorded(Box::new(
                        changed_worktree,
                    ))],
                    9,
                ),
                14,
            )
            .unwrap();
        assert!(
            moved
                .inventory_context(&fact.context, None)
                .unwrap()
                .post_restoration_completion()
                .is_none()
        );
        assert_eq!(
            context_a.restoration_boundary,
            context_b.restoration_boundary
        );
        let preview = super::super::derive_repository_scope_purge_preview(
            committed.repository_scope_preview_inputs(),
            repository.repository_id,
            2,
            false,
        )
        .unwrap();
        assert_eq!(
            preview.exclusive_cas_refs,
            vec!["a".repeat(64), "b".repeat(64)]
        );

        let mut disabled = committed.repositories[&repository.repository_id].0.clone();
        disabled.repository_revision = 3;
        disabled.predecessor_revision = Some(2);
        disabled.recorded_at_us = 4;
        disabled.user_disabled = true;
        let disabled_state = committed
            .apply_command(
                &repository_command(disabled.clone(), SourceKind::Manual, 4),
                8,
            )
            .unwrap();
        let mut revoked = disabled.clone();
        revoked.repository_revision = 4;
        revoked.predecessor_revision = Some(3);
        revoked.recorded_at_us = 5;
        revoked.capability_state.as_mut().unwrap().trust_revoked = true;
        let revoked_state = disabled_state
            .apply_command(
                &repository_command(revoked.clone(), SourceKind::System, 5),
                9,
            )
            .unwrap();
        let mut illicit = revoked;
        illicit.repository_revision = 5;
        illicit.predecessor_revision = Some(4);
        illicit.recorded_at_us = 6;
        illicit.user_disabled = false;
        assert!(
            revoked_state
                .apply_command(
                    &repository_command(illicit.clone(), SourceKind::Manual, 6),
                    10
                )
                .is_err()
        );
        illicit.user_disabled = true;
        illicit.capability_state = None;
        assert!(
            revoked_state
                .apply_command(&repository_command(illicit, SourceKind::System, 6), 10)
                .is_err()
        );
        let closure = super::super::RepositoryClosureKeys {
            repository_id: Some(repository.repository_id),
            ..Default::default()
        };
        assert!(
            closure
                .references_payload(&JournalPayload::CapabilityInventoryRecorded(Box::new(fact)))
        );
    }
}
