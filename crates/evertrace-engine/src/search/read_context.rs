//! Request-local read admission facts shared by native presentations, never a search cache.

use std::time::Instant;

use evertrace_domain::{
    error::ErrorCode,
    query::{
        ExactFieldsQuery, ExactReadQuery, ExactRecordQuery, ExactRecordRef, MetadataReadOutcome,
    },
};
use evertrace_store::{JournalPayload, ObjectRow, projections::StoredFieldsContext};

use crate::{WriterHandle, repository::RepositoryReadAuthority};

/// Assess only the canonical source and repository closure; observation recording belongs to callers.
pub(crate) async fn check_source_access(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    all_rows: &[ObjectRow],
    rows: &[&ObjectRow],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    for chunk in rows.chunks(usize::from(evertrace_domain::query::METADATA_READ_LIMIT)) {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted);
        }
        if !crate::session_import::source_rows_read_assessment(
            writer,
            authority,
            all_rows,
            chunk,
            None,
            Some(deadline),
        )
        .await
        .map_err(|_| ErrorCode::StoreCorrupt)?
        .0
        .is_empty()
        {
            return Err(ErrorCode::Untrusted);
        }
    }
    let scopes = crate::repository::row_repository_contexts_from_scopes(all_rows.iter(), rows)
        .map_err(|_| ErrorCode::StoreCorrupt)?;
    if !crate::repository::repository_read_assessment(
        writer,
        scopes.values().flatten().copied().collect(),
        authority,
        deadline,
    )
    .await
    .map_err(|_| ErrorCode::StoreCorrupt)?
    .0
    .is_empty()
    {
        return Err(ErrorCode::Untrusted);
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::ResourceExhausted);
    }
    Ok(())
}

pub(crate) fn source_receipt<'a>(
    reference: &str,
    find_row: impl Fn(&str) -> Option<&'a ObjectRow>,
) -> Option<Box<evertrace_domain::evidence::SourceReceipt>> {
    // Resolve stable public source/span identities, not an indexed timestamp.
    let observation_id = reference
        .parse::<evertrace_domain::ids::SourceObservationId>()
        .ok()
        .or_else(|| {
            evertrace_domain::evidence::EvidenceSurface::parse_candidate_ref(reference)
                .map(|value| value.0)
        })?;
    let reference = observation_id.to_string();
    let key = format!("object:evidence:source_observation:{reference}");
    let row = find_row(&key)?;
    let JournalPayload::SourceObservationRecorded(observation) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    let key = format!(
        "object:evidence:source_receipt:{}",
        observation.source_receipt_ref
    );
    let row = find_row(&key)?;
    let JournalPayload::SourceReceiptRecorded(receipt) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if receipt.source_observation_id.to_string() != reference
        || receipt.source_receipt_id != observation.source_receipt_ref
        || receipt.source_instance_id != observation.source_instance_id
        || receipt.source_revision != observation.source_revision
        || receipt.validate().is_err()
    {
        return None;
    }
    Some(receipt)
}

/// Use the existing bounded exact-read dependencies for scoped search candidates.
/// A bare index scope is not proof that the source of its text remains readable.
pub(crate) struct SearchReadAccess<'a> {
    pub writer: &'a WriterHandle,
    pub authority: RepositoryReadAuthority<'a>,
    pub frontier: u64,
    pub config_hash: [u8; 32],
    pub deadline: Instant,
}

/// Ordinary Search families whose public current revision and source/scope closure use exact reads.
pub(crate) const SCOPED_OBJECT_KINDS: &[&str] = &[
    "atom_revision",
    "task",
    "workstream",
    "work_episode",
    "attempt",
    "procedure_revision",
    "revision_proposal_revision",
    "semantic_digest",
];

impl SearchReadAccess<'_> {
    pub async fn check_revision(&self, revision: &str) -> Result<(), ErrorCode> {
        self.check(
            ExactReadQuery::Fields(ExactFieldsQuery {
                revision_ref: revision.to_owned(),
            }),
            revision,
            "atom_revision",
        )
        .await
        .map(drop)
    }

    /// A lagging index may offer an immutable revision; only its current alias can grant Search access.
    pub(crate) async fn check_current(
        &self,
        key: &str,
        revision: &str,
        kind: &str,
    ) -> Result<(), ErrorCode> {
        let context = self.check_record(key, revision, kind).await?;
        let row = context.selected.as_ref().ok_or(ErrorCode::StoreCorrupt)?;
        if row.object_id.as_deref() != Some(key) {
            return Err(ErrorCode::StoreCorrupt);
        }
        if matches!(
            kind,
            "procedure_revision" | "revision_proposal_revision" | "semantic_digest"
        ) {
            // A missing or suppressed dependency is not permission to use compiled text.
            let present = |reference: &str| {
                context.rows.iter().any(|fact| {
                    fact.object_id.as_deref() == Some(reference)
                        || fact.current_revision_id.as_deref() == Some(reference)
                })
            };
            let payload =
                serde_json::from_str(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
                    .map_err(|_| ErrorCode::StoreCorrupt)?;
            let draft = match &payload {
                JournalPayload::ProcedureRevisionRecorded(procedure) => &procedure.draft,
                JournalPayload::RevisionProposalRecorded(proposal) => {
                    let evertrace_domain::semantic::ProposalPayload::Procedure(method) =
                        &proposal.payload
                    else {
                        return Err(ErrorCode::Untrusted);
                    };
                    if !proposal
                        .source_cohort_refs
                        .iter()
                        .chain(&proposal.evidence_refs)
                        .all(|id| present(id))
                    {
                        return Err(ErrorCode::Untrusted);
                    }
                    method.draft()
                }
                JournalPayload::SemanticDigestRecorded(digest) => {
                    return if digest.selected_direct_refs.iter().all(|id| present(id))
                        && digest
                            .episode_revision_id
                            .is_none_or(|id| present(&id.to_string()))
                    {
                        Ok(())
                    } else {
                        Err(ErrorCode::Untrusted)
                    };
                }
                _ => return Err(ErrorCode::StoreCorrupt),
            };
            if draft.evidence_refs.iter().any(|id| !present(id))
                || draft
                    .support_revision_refs
                    .iter()
                    .any(|id| !present(&id.to_string()))
            {
                return Err(ErrorCode::Untrusted);
            }
        }
        if kind == "work_episode" {
            let JournalPayload::WorkEpisodeRecorded(episode) =
                serde_json::from_str(row.payload_json.as_deref().ok_or(ErrorCode::StoreCorrupt)?)
                    .map_err(|_| ErrorCode::StoreCorrupt)?
            else {
                return Err(ErrorCode::StoreCorrupt);
            };
            if episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Closed {
                return Ok(());
            }
            let read_payload = |kind: &str, reference: &str| {
                context
                    .rows
                    .iter()
                    .find(|row| {
                        row.object_kind.as_deref() == Some(kind)
                            && row.object_id.as_deref() == Some(reference)
                    })
                    .and_then(|row| row.payload_json.as_deref())
                    .ok_or(ErrorCode::Untrusted)
            };
            if let Some(snapshot) = episode
                .exit_worktree_snapshot_id
                .or(episode.entry_worktree_snapshot_id)
            {
                let payload = read_payload("worktree_snapshot", &snapshot.to_string())?;
                if !matches!(serde_json::from_str::<JournalPayload>(payload),
                    Ok(JournalPayload::WorktreeSnapshotRecorded(snapshot))
                        if Some(snapshot.worktree_instance_id) == episode.worktree_instance_id)
                {
                    return Err(ErrorCode::Untrusted);
                }
            } else if let Some(worktree) = episode.worktree_instance_id {
                let payload = read_payload("worktree", &worktree.to_string())?;
                if !matches!(serde_json::from_str::<JournalPayload>(payload),
                    Ok(JournalPayload::WorktreeInstanceRecorded(tree))
                        if tree.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active)
                {
                    return Err(ErrorCode::ResourceExhausted);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn check_evidence(&self, source: &str) -> Result<(), ErrorCode> {
        self.check_record(source, source, "source_observation")
            .await
            .map(drop)
    }

    pub(super) async fn checked_source_receipt(
        &self,
        source: &str,
    ) -> Result<Box<evertrace_domain::evidence::SourceReceipt>, ErrorCode> {
        let context = self
            .check_record(source, source, "source_observation")
            .await?;
        source_receipt(source, |key| {
            context.rows.iter().find(|row| row.row_id == key)
        })
        .ok_or(ErrorCode::StoreCorrupt)
    }

    async fn check_record(
        &self,
        key: &str,
        revision: &str,
        kind: &str,
    ) -> Result<Box<StoredFieldsContext>, ErrorCode> {
        let query = ExactReadQuery::Record(ExactRecordQuery {
            reference: ExactRecordRef {
                stable_key: key.to_owned(),
                revision_ref: None,
            },
            field: None,
            range: None,
            expected_data_identity: None,
            expected_selection: None,
        });
        self.check(query, revision, kind).await
    }

    async fn check(
        &self,
        query: ExactReadQuery,
        revision: &str,
        kind: &str,
    ) -> Result<Box<StoredFieldsContext>, ErrorCode> {
        let read = async {
            let (cancelled, _cancel_on_drop) =
                evertrace_store::StoreReadHandle::cancellation_scope();
            let MetadataReadOutcome::Page(context) = self
                .writer
                .read_stored_fields_context(
                    Box::new(query),
                    cancelled,
                    self.deadline,
                    self.config_hash,
                )
                .await
                .map_err(|_| ErrorCode::StoreCorrupt)?
            else {
                return Err(ErrorCode::ResourceExhausted);
            };
            if context.state.frontier != self.frontier
                || context.selected.as_ref().is_none_or(|row| {
                    row.current_revision_id.as_deref() != Some(revision)
                        || row.object_kind.as_deref() != Some(kind)
                })
            {
                return Err(ErrorCode::StoreCorrupt);
            }
            if context.source_suppressed {
                return Err(ErrorCode::Untrusted);
            }
            let refs = context.rows.iter().collect::<Vec<_>>();
            check_source_access(
                self.writer,
                &self.authority,
                &context.rows,
                &refs,
                self.deadline,
            )
            .await?;
            let state = self
                .writer
                .read_handle()
                .state()
                .await
                .map_err(|_| ErrorCode::StoreCorrupt)?;
            if state != (self.frontier, context.state.data_identity) {
                return Err(ErrorCode::StoreCorrupt);
            }
            Ok(context)
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(self.deadline), read)
            .await
            .map_err(|_| ErrorCode::ResourceExhausted)?
    }
}
