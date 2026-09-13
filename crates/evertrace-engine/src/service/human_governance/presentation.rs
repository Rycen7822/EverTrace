use super::*;

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HumanSemanticContent {
    Atom(Box<evertrace_domain::semantic::Atom>),
    Procedure(Box<evertrace_domain::procedure::ProcedureRevision>),
    CoreMembership(Box<evertrace_domain::semantic::CoreMembership>),
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanContentState {
    Ready,
    TooLarge,
    AccessDenied,
    Missing,
    Unsupported,
    Unavailable,
}

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
const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

impl HumanGovernanceService {
    pub(super) async fn semantic_details(
        &self,
        snapshot: &ProjectionSnapshot,
        items: &mut [HumanSummary],
    ) -> Result<(), HumanGovernanceError> {
        let deadline = std::time::Instant::now() + READ_DEADLINE;
        for item in items {
            let Some(row) = snapshot.row(&item.stable_key) else {
                continue;
            };
            if !matches!(
                row.object_kind.as_deref(),
                Some(
                    "atom_revision"
                        | "procedure_revision"
                        | "core_membership"
                        | "revision_proposal_revision"
                )
            ) {
                continue;
            }
            // Candidate and base have separate access decisions. A missing base
            // must never change proposal eligibility or substitute the current revision.
            match self.readable_row(snapshot, row, deadline).await {
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

fn access_state(error: export::Failure) -> HumanContentState {
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

fn present(row: &ObjectRow) -> Result<HumanSemanticDetail, HumanGovernanceError> {
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?,
    )
    .map_err(|_| HumanGovernanceError::Store)?;
    let (content, preview, object, revision) = match payload {
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
        _ => {
            return Ok(unavailable(
                row.object_id.clone(),
                row.current_revision_id.clone(),
                HumanContentState::Unsupported,
            ));
        }
    };
    if row.object_id.as_deref() != Some(object.as_str())
        || row.current_revision_id.as_deref() != Some(revision.as_str())
    {
        return Err(HumanGovernanceError::Store);
    }
    let original_bytes = serde_json::to_vec(&content)
        .map_err(|_| HumanGovernanceError::Store)?
        .len();
    let fits = original_bytes <= MAX_CONTENT_BYTES;
    Ok(HumanSemanticDetail {
        object_ref: Some(object),
        revision_ref: Some(revision),
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
