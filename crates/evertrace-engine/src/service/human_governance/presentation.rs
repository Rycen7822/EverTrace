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

fn native_directory_hint(receipt: &evertrace_domain::evidence::SourceReceipt) -> Option<String> {
    use evertrace_domain::evidence::{EvidenceSourceKind, ProtectedPresentation};
    if receipt.source_kind != EvidenceSourceKind::CodexHook || receipt.validate().is_err() {
        return None;
    }
    let ProtectedPresentation::Inline { text } = receipt.protected_presentation.as_ref()? else {
        return None;
    };
    // Only complete protected native input is a display hint; never parse a preview
    // or read CAS here, and never use this hint as repository or session authority.
    if text.len() > MAX_CONTENT_BYTES || text.len() as u64 != receipt.protected_length {
        return None;
    }
    native_inline_directory_hint(text, &receipt.source_session_ref)
}

fn native_inline_directory_hint(text: &str, source_session_ref: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    if value.get("session_id")?.as_str()? != source_session_ref {
        return None;
    }
    value
        .get("cwd")?
        .as_str()
        .filter(|value| {
            value.starts_with('/')
                && value.len() <= 4096
                && !value.chars().any(char::is_control)
                && !std::path::Path::new(value)
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
        })
        .map(str::to_owned)
}

impl HumanGovernanceService {
    pub(super) async fn source_contexts(
        &self,
        snapshot: &ProjectionSnapshot,
        items: &mut [HumanSummary],
    ) -> Result<(), HumanGovernanceError> {
        if !items.iter().any(|item| {
            matches!(
                item.object_kind.as_str(),
                "source_receipt" | "source_observation" | "host_occurrence"
            )
        }) {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + READ_DEADLINE;
        let index = export::presentation_index(snapshot, deadline)
            .map_err(|_| HumanGovernanceError::Store)?;
        let sessions =
            evertrace_store::session_import::SessionImportCurrentView::from_snapshot(snapshot)
                .map_err(|_| HumanGovernanceError::Store)?;
        let mut sources = BTreeMap::<&str, Vec<&evertrace_store::SessionImportCurrent>>::new();
        for session in sessions.sessions.values() {
            if let Some(source) = session.source_instance_id.as_deref() {
                sources.entry(source).or_default().push(session);
            }
        }
        for item in items {
            if !matches!(
                item.object_kind.as_str(),
                "source_receipt" | "source_observation" | "host_occurrence"
            ) {
                continue;
            }
            let Some(row) = snapshot.row(&item.stable_key) else {
                continue;
            };
            match self
                .readable_indexed_row(snapshot, row, &index, deadline)
                .await
            {
                Ok(()) => {}
                Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                Err(_) => {
                    item.source_context = None;
                    continue;
                }
            }
            let decode = |row: &ObjectRow| -> Result<JournalPayload, HumanGovernanceError> {
                let value: JournalPayload = serde_json::from_str(
                    row.payload_json
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
                value.validate().map_err(|_| HumanGovernanceError::Store)?;
                Ok(value)
            };
            let exact = |reference: &str| -> Option<&ObjectRow> {
                let rows = index.get(reference)?;
                (rows.len() == 1).then(|| rows[0])
            };
            let payload = match decode(row)? {
                JournalPayload::HostOccurrenceNormalized(value)
                    if value.source_observation_refs.len() == 1 =>
                {
                    let Some(source) = exact(&value.source_observation_refs[0].to_string()) else {
                        continue;
                    };
                    decode(source)?
                }
                value => value,
            };
            let receipt = match payload {
                JournalPayload::SourceReceiptRecorded(value) => value,
                JournalPayload::SourceObservationRecorded(value) => {
                    let Some(source) = exact(&value.source_receipt_ref.to_string()) else {
                        continue;
                    };
                    let JournalPayload::SourceReceiptRecorded(receipt) = decode(source)? else {
                        continue;
                    };
                    if receipt.source_observation_id != value.source_observation_id {
                        continue;
                    }
                    receipt
                }
                _ => continue,
            };
            // Host occurrence permissions alone do not authorize its source body.
            let Some(receipt_row) = exact(&receipt.source_receipt_id.to_string()) else {
                continue;
            };
            match self
                .readable_indexed_row(snapshot, receipt_row, &index, deadline)
                .await
            {
                Ok(()) => {}
                Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                Err(_) => continue,
            }
            let directory = sources
                .get(receipt.source_instance_id.as_str())
                .filter(|matches| matches.len() == 1)
                .map(|matches| matches[0])
                .filter(|session| session.metadata.source_revision == receipt.source_revision)
                .and_then(|session| session.metadata.workspace_hint.clone())
                .or_else(|| native_directory_hint(&receipt));
            item.source_context = Some(HumanSourceContext {
                directory: directory.filter(|value| !value.is_empty() && value.len() <= 4096),
                session: receipt.source_session_ref.clone(),
                event_time_us: receipt.event_time_us,
                recorded_at_us: receipt.recorded_at_us,
            });
        }
        Ok(())
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

#[cfg(test)]
mod native_hint_tests {
    use super::native_inline_directory_hint;

    #[test]
    fn native_directory_requires_matching_session_and_literal_absolute_path() {
        let input = r#"{"session_id":"session-a","cwd":"/workspace/project"}"#;
        assert_eq!(
            native_inline_directory_hint(input, "session-a").as_deref(),
            Some("/workspace/project")
        );
        assert_eq!(native_inline_directory_hint(input, "session-b"), None);
        for path in [
            "",
            "relative/path",
            "/work/../other",
            "/work\nspoof",
            "/work\u{1b}[31m",
        ] {
            let input = serde_json::json!({"session_id":"session-a", "cwd":path}).to_string();
            assert_eq!(native_inline_directory_hint(&input, "session-a"), None);
        }
    }
}
