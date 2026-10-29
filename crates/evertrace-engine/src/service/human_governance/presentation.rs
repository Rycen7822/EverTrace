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

fn source_context_fields(
    receipt: &evertrace_domain::evidence::SourceReceipt,
    directory: Option<String>,
) -> HumanSourceContext {
    HumanSourceContext {
        directory: directory
            .or_else(|| native_directory_hint(receipt))
            .filter(|value| !value.is_empty() && value.len() <= 4096),
        session: receipt.source_session_ref.clone(),
        event_time_us: receipt.event_time_us,
        recorded_at_us: receipt.recorded_at_us,
    }
}

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
    pub(super) async fn capture_page(
        &self,
        context: evertrace_store::CaptureCurrentContext,
        detail: bool,
    ) -> Result<HumanPage, HumanGovernanceError> {
        let deadline = std::time::Instant::now() + READ_DEADLINE;
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        let mut items = Vec::with_capacity(context.items.len());
        for current in context.items {
            let mut item = summary_fields(&current.selected, HumanSurface::Explorer);
            if detail {
                item.evidence_detail = source_evidence_detail_from_rows(&current.selected, |id| {
                    current.source_rows.iter().find(|row| row.row_id == id)
                })?;
            }
            let mut sources = BTreeMap::new();
            let mut receipt = None;
            let mut observation = None;
            for row in &current.source_rows {
                let payload: JournalPayload = serde_json::from_str(
                    row.payload_json
                        .as_deref()
                        .ok_or(HumanGovernanceError::Store)?,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
                match payload {
                    JournalPayload::SourceReceiptRecorded(value) => {
                        sources.insert(
                            row.row_id.clone(),
                            value.source_instance_id.as_str().to_owned(),
                        );
                        receipt = Some(value);
                    }
                    JournalPayload::SourceObservationRecorded(value) => {
                        sources.insert(
                            row.row_id.clone(),
                            value.source_instance_id.as_str().to_owned(),
                        );
                        observation = Some(value);
                    }
                    JournalPayload::EvidenceSurfaceRecorded(_) => {}
                    _ => return Err(HumanGovernanceError::Store),
                }
            }
            if let Some(observation) = &observation {
                for row in current
                    .source_rows
                    .iter()
                    .filter(|row| row.object_kind.as_deref() == Some("evidence_surface"))
                {
                    sources.insert(
                        row.row_id.clone(),
                        observation.source_instance_id.as_str().to_owned(),
                    );
                }
            }
            let blocked = crate::session_import::blocked_source_instances(
                &self.writer,
                report.as_ref(),
                sources
                    .get(&current.selected.row_id)
                    .map(|source| (current.selected.row_id.clone(), source.clone()))
                    .into_iter()
                    .collect(),
                self.effective_config_hash,
                None,
            )
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
            let rows = current.source_rows.iter().collect::<Vec<_>>();
            let selected_rows = [&current.selected];
            let selected_scopes = crate::repository::row_repository_contexts_from_scopes(
                current.scope_rows.iter(),
                &selected_rows,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let selected_repositories = crate::repository::blocked_repositories(
                &self.writer,
                selected_scopes.values().flatten().copied().collect(),
                report.as_ref(),
                self.effective_config_hash,
            )
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
            if blocked.contains(&current.selected.row_id) || !selected_repositories.is_empty() {
                item.evidence_detail = None;
            }
            let paired =
                receipt
                    .as_ref()
                    .zip(observation.as_ref())
                    .filter(|(receipt, observation)| {
                        receipt.source_receipt_id == observation.source_receipt_ref
                            && receipt.source_observation_id == observation.source_observation_id
                    });
            if let Some((receipt, _)) = paired
                && export::source_metadata_budget(&rows, deadline).is_ok()
            {
                let report = match &self.session_report {
                    Some(report) => report.read().await.clone(),
                    None => None,
                };
                let blocked = crate::session_import::blocked_source_instances(
                    &self.writer,
                    report.as_ref(),
                    sources,
                    self.effective_config_hash,
                    None,
                )
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
                if !blocked.is_empty() {
                    items.push(item);
                    continue;
                }
                // Keep the direct-cohort gate separate from selected-row body
                // access, including its per-cohort repository cardinality.
                let scopes = crate::repository::row_repository_contexts_from_scopes(
                    current.scope_rows.iter(),
                    &rows,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
                let repositories = crate::repository::blocked_repositories(
                    &self.writer,
                    scopes.values().flatten().copied().collect(),
                    report.as_ref(),
                    self.effective_config_hash,
                )
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
                if repositories.is_empty()
                    && !current.suppressed
                    && export::check_deadline(deadline).is_ok()
                {
                    item.source_context = Some(source_context_fields(receipt, current.directory));
                }
            }
            items.push(item);
        }
        let (status, degraded_reasons) = failed_job_status(context.has_failed_job);
        Ok(HumanPage {
            diagnostics: None,
            frontier: context.frontier,
            status,
            degraded_reasons,
            items,
            next_cursor: context.next_cursor,
        })
    }

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
            item.source_context = None;
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
            let (observation_id, selected_receipt_id) = match decode(row)? {
                JournalPayload::HostOccurrenceNormalized(value)
                    if value.source_observation_refs.len() == 1 =>
                {
                    (value.source_observation_refs[0], None)
                }
                JournalPayload::SourceReceiptRecorded(value) => {
                    (value.source_observation_id, Some(value.source_receipt_id))
                }
                JournalPayload::SourceObservationRecorded(value) => {
                    (value.source_observation_id, None)
                }
                _ => continue,
            };
            // Use exact fact rows: a surface shares its observation's revision
            // alias, but is a separate member of the direct permission cohort.
            let Some(observation_row) = exact(&format!(
                "object:evidence:source_observation:{observation_id}"
            )) else {
                continue;
            };
            let JournalPayload::SourceObservationRecorded(observation) = decode(observation_row)?
            else {
                continue;
            };
            let Some(receipt_row) = exact(&format!(
                "object:evidence:source_receipt:{}",
                observation.source_receipt_ref
            )) else {
                continue;
            };
            let JournalPayload::SourceReceiptRecorded(receipt) = decode(receipt_row)? else {
                continue;
            };
            if observation.source_observation_id != observation_id
                || receipt.source_observation_id != observation_id
                || receipt.source_receipt_id != observation.source_receipt_ref
                || selected_receipt_id.is_some_and(|id| id != receipt.source_receipt_id)
            {
                continue;
            }
            let mut direct = vec![row, observation_row, receipt_row];
            if let Some(surfaces) =
                index.get(format!("projection:evidence_surface:{observation_id}").as_str())
            {
                if surfaces.len() != 1 {
                    continue;
                }
                let surface_row = surfaces[0];
                let JournalPayload::EvidenceSurfaceRecorded(surface) = decode(surface_row)? else {
                    continue;
                };
                if surface.source_observation_revision_ref != observation_id {
                    continue;
                }
                direct.push(surface_row);
            }
            direct.sort_by(|left, right| left.row_id.cmp(&right.row_id));
            direct.dedup_by(|left, right| left.row_id == right.row_id);
            // Task and Worktree resolve these rows' actual scopes; their
            // unrelated evidence links are not authority for source hints.
            match self.readable_source_rows(snapshot, &direct, deadline).await {
                Ok(()) => {}
                Err(export::Failure::Corrupt) => return Err(HumanGovernanceError::Store),
                Err(_) => continue,
            };
            let directory = sources
                .get(receipt.source_instance_id.as_str())
                .filter(|matches| matches.len() == 1)
                .map(|matches| matches[0])
                .filter(|session| session.metadata.source_revision == receipt.source_revision)
                .and_then(|session| session.metadata.workspace_hint.clone());
            item.source_context = Some(source_context_fields(&receipt, directory));
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
