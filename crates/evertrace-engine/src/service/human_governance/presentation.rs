use super::*;

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HumanSemanticContent {
    Digest(Box<evertrace_domain::semantic::SemanticDigest>),
    Atom(Box<evertrace_domain::semantic::Atom>),
    Procedure(Box<evertrace_domain::procedure::ProcedureRevision>),
    CoreMembership(Box<evertrace_domain::semantic::CoreMembership>),
}

pub use evertrace_domain::query::HumanContentState;

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSemanticDetail {
    pub object_ref: Option<String>,
    pub revision_ref: Option<String>,
    pub state: HumanContentState,
    pub preview: Option<String>,
    pub original_bytes: u64,
    pub content: Option<HumanSemanticContent>,
}

const MAX_CONTENT_BYTES: usize = 32 * 1024;
pub(super) const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

pub(super) fn display_name(value: &str) -> String {
    value
        .split(|ch: char| ch.is_whitespace() || ch.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn capture_page(context: evertrace_store::CaptureCurrentContext) -> HumanPage {
    let items = context
        .items
        .iter()
        .map(|current| summary_fields(&current.selected, HumanSurface::Explorer))
        .collect();
    let (status, degraded_reasons) = failed_job_status(context.has_failed_job);
    HumanPage {
        diagnostics: None,
        frontier: context.frontier,
        status,
        degraded_reasons,
        items,
        next_cursor: context.next_cursor,
    }
}

impl HumanGovernanceService {
    pub async fn web_core_anchor(
        &self,
        proposal: &RevisionProposal,
        frontier: u64,
    ) -> Result<Option<HumanSemanticDetail>, HumanGovernanceError> {
        if proposal.core_creation().is_none() {
            return Ok(None);
        }
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != frontier {
            return Ok(None);
        }
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        self.web_core_anchor_at(&snapshot, &view, proposal).await
    }

    pub(crate) async fn web_core_anchor_at(
        &self,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        proposal: &RevisionProposal,
    ) -> Result<Option<HumanSemanticDetail>, HumanGovernanceError> {
        let Some((revision, scope)) = proposal.core_creation() else {
            return Ok(None);
        };
        let Some(atom) = scope.reviewable_atom(revision, view.atoms.values()) else {
            return Ok(None);
        };
        let reference = revision.to_string();
        let Some((row, _)) = super::super::actions::select_object_row(snapshot, &reference)
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(None);
        };
        if row.object_kind.as_deref() != Some("atom_revision")
            || row.current_revision_id.as_deref() != Some(reference.as_str())
        {
            return Err(HumanGovernanceError::Store);
        }
        match self
            .readable_row(snapshot, row, std::time::Instant::now() + READ_DEADLINE)
            .await
        {
            Ok(()) => {
                let detail = present(row)?;
                match detail.content.as_ref() {
                    Some(HumanSemanticContent::Atom(value)) if value.as_ref() == atom => {
                        Ok(Some(detail))
                    }
                    None => Ok(None),
                    _ => Err(HumanGovernanceError::Store),
                }
            }
            Err(export::Failure::Denied) => Ok(None),
            Err(_) => Err(HumanGovernanceError::Store),
        }
    }

    pub async fn web_merge_accessible(
        &self,
        proposal: &RevisionProposal,
        frontier: u64,
    ) -> Result<bool, HumanGovernanceError> {
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if frontier != snapshot.frontier {
            return Ok(false);
        }
        self.web_merge_accessible_at(&snapshot, proposal).await
    }

    pub(crate) async fn web_merge_accessible_at(
        &self,
        snapshot: &ProjectionSnapshot,
        proposal: &RevisionProposal,
    ) -> Result<bool, HumanGovernanceError> {
        let Some(inputs) = proposal.atom_merge_inputs() else {
            return Ok(true);
        };
        let mut pending = inputs
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let deadline = std::time::Instant::now() + READ_DEADLINE;
        let index = export::presentation_index(snapshot, deadline)
            .map_err(|_| HumanGovernanceError::Store)?;
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
        {
            if !row
                .current_revision_id
                .as_deref()
                .is_some_and(|id| pending.remove(id))
            {
                continue;
            }
            match self
                .readable_indexed_row(snapshot, row, &index, deadline)
                .await
            {
                Ok(()) => (),
                Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                Err(_) => return Ok(false),
            }
            if pending.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) async fn web_procedure_base_accessible(
        &self,
        snapshot: &ProjectionSnapshot,
        proposal: &RevisionProposal,
    ) -> Result<bool, HumanGovernanceError> {
        let Some(ProposalTargetId::Procedure(id)) = proposal.target_id else {
            return Ok(proposal.base_revision_id.is_none());
        };
        let Some(base) = proposal.base_revision_id else {
            return Ok(false);
        };
        let reference = base.to_string();
        let Some((row, true)) = super::super::actions::select_object_row(snapshot, &reference)
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(false);
        };
        if row.object_kind.as_deref() != Some("procedure_revision")
            || row.object_id.as_deref() != Some(id.to_string().as_str())
            || row.current_revision_id.as_deref() != Some(reference.as_str())
        {
            return Ok(false);
        }
        match self
            .readable_row(snapshot, row, std::time::Instant::now() + READ_DEADLINE)
            .await
        {
            Ok(()) => Ok(true),
            Err(export::Failure::Denied) => Ok(false),
            Err(_) => Err(HumanGovernanceError::Store),
        }
    }

    pub(super) async fn semantic_details(
        &self,
        snapshot: &ProjectionSnapshot,
        items: &mut [HumanSummary],
    ) -> Result<(), HumanGovernanceError> {
        if !items.iter().any(|item| {
            matches!(
                item.object_kind.as_str(),
                "atom_revision"
                    | "procedure_revision"
                    | "core_membership"
                    | "revision_proposal_revision"
                    | "semantic_digest"
            )
        }) {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + READ_DEADLINE;
        let index = export::presentation_index(snapshot, deadline)
            .map_err(|_| HumanGovernanceError::Store)?;
        for item in items {
            let Some(row) = snapshot.row(&item.stable_key) else {
                continue;
            };
            if !matches!(
                row.object_kind.as_deref(),
                Some(
                    "atom_revision"
                        | "semantic_digest"
                        | "procedure_revision"
                        | "core_membership"
                        | "revision_proposal_revision"
                )
            ) {
                continue;
            }
            // Candidate and base have separate access decisions. A missing base
            // must never change proposal eligibility or substitute the current revision.
            match self
                .readable_indexed_row(snapshot, row, &index, deadline)
                .await
            {
                Ok(()) => {}
                Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                Err(error) => {
                    item.proposal_review = None;
                    item.semantic_detail = Some(unavailable(
                        row.object_id.clone(),
                        row.current_revision_id.clone(),
                        access_state(error),
                    ));
                    continue;
                }
            }
            if row.object_kind.as_deref() != Some("revision_proposal_revision") {
                item.semantic_detail = Some(present(row)?);
            }
            if let Some(proposal) = &item.proposal {
                let Some(base) = proposal.base_revision_id else {
                    continue;
                };
                let reference = base.to_string();
                let selected = super::super::actions::select_object_row(snapshot, &reference)
                    .map_err(|_| HumanGovernanceError::Store)?;
                let Some((base_row, _)) = selected else {
                    item.proposal_base = Some(unavailable(
                        None,
                        Some(reference),
                        HumanContentState::Missing,
                    ));
                    continue;
                };
                let target_matches = match proposal.target_id {
                    Some(ProposalTargetId::Atom(id)) => {
                        base_row.object_kind.as_deref() == Some("atom_revision")
                            && base_row.object_id.as_deref() == Some(id.to_string().as_str())
                    }
                    Some(ProposalTargetId::Procedure(id)) => {
                        base_row.object_kind.as_deref() == Some("procedure_revision")
                            && base_row.object_id.as_deref() == Some(id.to_string().as_str())
                    }
                    Some(ProposalTargetId::CoreMembership(id)) => {
                        base_row.object_kind.as_deref() == Some("core_membership")
                            && base_row.object_id.as_deref() == Some(id.to_string().as_str())
                    }
                    None => false,
                };
                if !target_matches
                    || base_row.current_revision_id.as_deref() != Some(reference.as_str())
                {
                    item.proposal_base = Some(unavailable(
                        None,
                        Some(reference),
                        HumanContentState::Missing,
                    ));
                    continue;
                }
                item.proposal_base = Some(
                    match self.readable_row(snapshot, base_row, deadline).await {
                        Ok(()) => present(base_row)?,
                        Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                        Err(error) => unavailable(
                            base_row.object_id.clone(),
                            Some(reference),
                            access_state(error),
                        ),
                    },
                );
            }
        }
        Ok(())
    }
}

pub(super) fn access_state(error: export::Failure) -> HumanContentState {
    match error {
        export::Failure::Denied => HumanContentState::AccessDenied,
        _ => HumanContentState::Unavailable,
    }
}

fn unavailable(
    object_ref: Option<String>,
    revision_ref: Option<String>,
    state: HumanContentState,
) -> HumanSemanticDetail {
    HumanSemanticDetail {
        object_ref,
        revision_ref,
        state,
        preview: None,
        original_bytes: 0,
        content: None,
    }
}

pub(super) fn semantic_value(
    row: &ObjectRow,
) -> Result<Option<(HumanSemanticContent, Option<String>)>, HumanGovernanceError> {
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?,
    )
    .map_err(|_| HumanGovernanceError::Store)?;
    let (content, preview, object, revision) = match payload {
        JournalPayload::SemanticDigestRecorded(value) => {
            value.validate().map_err(|_| HumanGovernanceError::Store)?;
            let preview = value
                .application
                .progress_delta
                .iter()
                .chain(&value.application.decision_delta)
                .chain(&value.application.outcome_delta)
                .chain(&value.application.open_loops)
                .chain(&value.application.failed_routes)
                .chain(&value.application.resolved_items)
                .next()
                .map(|delta| delta.value.chars().take(160).collect());
            let object = value.semantic_digest_id.to_string();
            (
                HumanSemanticContent::Digest(value),
                preview,
                object.clone(),
                object,
            )
        }
        JournalPayload::AtomRecorded(value) => {
            let preview = value.value.text.chars().take(160).collect::<String>();
            let object = value.atom_id.to_string();
            let revision = value.revision_id.to_string();
            (
                HumanSemanticContent::Atom(value),
                Some(preview),
                object,
                revision,
            )
        }
        JournalPayload::ProcedureRevisionRecorded(value) => {
            let preview = value.draft.title.chars().take(160).collect::<String>();
            let object = value.procedure_id.to_string();
            let revision = value.revision_id.to_string();
            (
                HumanSemanticContent::Procedure(value),
                Some(preview),
                object,
                revision,
            )
        }
        JournalPayload::CoreMembershipRecorded(value) => {
            let object = value.core_membership_id.to_string();
            let revision = value.membership_revision_id.to_string();
            (
                HumanSemanticContent::CoreMembership(value),
                None,
                object,
                revision,
            )
        }
        _ => return Ok(None),
    };
    if row.object_id.as_deref() != Some(object.as_str())
        || row.current_revision_id.as_deref() != Some(revision.as_str())
    {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some((content, preview)))
}

pub(super) fn present(row: &ObjectRow) -> Result<HumanSemanticDetail, HumanGovernanceError> {
    let Some((content, preview)) = semantic_value(row)? else {
        return Ok(unavailable(
            row.object_id.clone(),
            row.current_revision_id.clone(),
            HumanContentState::Unsupported,
        ));
    };
    let original_bytes = serde_json::to_vec(&content)
        .map_err(|_| HumanGovernanceError::Store)?
        .len();
    let fits = original_bytes <= MAX_CONTENT_BYTES;
    Ok(HumanSemanticDetail {
        object_ref: row.object_id.clone(),
        revision_ref: row.current_revision_id.clone(),
        state: if fits {
            HumanContentState::Ready
        } else {
            HumanContentState::TooLarge
        },
        preview,
        original_bytes: original_bytes as u64,
        content: fits.then_some(content),
    })
}
