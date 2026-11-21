use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{EvidenceSourceKind, EvidenceSurface, SourceReceipt, payload_fingerprint},
    revision::RevisionId,
    semantic::{SemanticDigest, SemanticDigestStatus, WikiProjection},
};

use crate::{
    JournalPayload, StoreError,
    search::{SEARCH_PROJECTION_GENERATION, SearchProjectionRow},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultRetrievalSuppressionGeneration {
    ObservationSpanV1,
    ContentSpanV2,
}

pub fn default_retrieval_suppression_ref_hash(
    surface: &EvidenceSurface,
    receipt: &SourceReceipt,
    generation: DefaultRetrievalSuppressionGeneration,
) -> Result<String, StoreError> {
    surface.validate().map_err(|_| StoreError::StoreCorrupt)?;
    receipt.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if receipt.source_observation_id != surface.source_observation_revision_ref {
        return Err(StoreError::StoreCorrupt);
    }
    let (version, span_identity) = match generation {
        DefaultRetrievalSuppressionGeneration::ObservationSpanV1 => (1, surface.span_hash.clone()),
        DefaultRetrievalSuppressionGeneration::ContentSpanV2 => (
            2,
            hex(payload_fingerprint(
                surface.canonicalization_version,
                surface.protected_text.as_bytes(),
                None,
            )
            .map_err(|_| StoreError::StoreCorrupt)?),
        ),
    };
    sha256(
        "evertrace_default_retrieval_suppression_ref",
        version,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(source_kind(receipt.source_kind).into()),
            CanonicalValue::String(receipt.identity_domain.clone()),
            CanonicalValue::String(receipt.source_record_identity.as_str().into()),
            CanonicalValue::Integer(i128::from(surface.canonicalization_version)),
            CanonicalValue::String(span_identity),
        ]),
    )
    .map(hex)
    .map_err(|_| StoreError::StoreCorrupt)
}

pub(super) fn wiki_search_row(
    projection: &WikiProjection,
    source_text: &[String],
    contradictions: &[[RevisionId; 2]],
    source_event_seq: u64,
) -> SearchProjectionRow {
    let mut fields = vec![format!("topic:{}", projection.topic)];
    fields.extend(source_text.iter().map(|value| format!("statement:{value}")));
    fields.extend(
        projection
            .source_atom_ids
            .iter()
            .map(|id| format!("source_atom:{id}")),
    );
    fields.extend(
        contradictions
            .iter()
            .flat_map(|pair| pair.iter().map(|id| format!("contradiction:{id}"))),
    );
    SearchProjectionRow {
        row_id: format!("search:object:wiki:{}", projection.page_id),
        row_variant: "object".into(),
        candidate_id: Some(projection.page_id.to_string()),
        source_ref: Some(projection.page_id.to_string()),
        source_kind: Some("object_projection".into()),
        text: bounded_search_text(&projection.page_id.to_string(), &fields),
        source_role: None,
        content_trust: None,
        capture_completeness: None,
        instruction_authority: "none".into(),
        object_kind: Some("wiki_projection".into()),
        currentness: Some("current".into()),
        lifecycle: Some("active".into()),
        epistemic: Some("derived".into()),
        authority: Some("none".into()),
        task_id: None,
        repository_id: None,
        worktree_id: None,
        event_time_us: 0,
        recorded_at_us: 0,
        source_sequence: projection.source_watermark,
        time_domain: "source_sequence".into(),
        retrieval_completeness: "complete".into(),
        suppression_ref_hash: None,
        source_event_seq,
        projection_generation: SEARCH_PROJECTION_GENERATION,
    }
}

pub(super) fn exact_identifier_row(
    row: &crate::ObjectRow,
    source_event_seq: u64,
    is_current: bool,
) -> Result<Option<SearchProjectionRow>, StoreError> {
    let Some(id) = row.object_id.as_ref() else {
        return Ok(None);
    };
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let Some((semantic, event_time_us)) = allowlisted_object_text(
        &payload,
        (8_usize * 1024).saturating_sub(id.len().saturating_add(1)),
    ) else {
        return Ok(None);
    };
    object_identifier_row(
        row,
        &payload,
        is_current,
        semantic,
        event_time_us,
        source_event_seq,
    )
    .map(Some)
}

/// An assignment endpoint is visible only through a proven current typed relation, not FTS.
pub fn canonical_work_binding_source(
    row: &crate::ObjectRow,
) -> Result<SearchProjectionRow, StoreError> {
    row.validate()?;
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let JournalPayload::WorkBindingRecorded(binding) = &payload else {
        return Err(StoreError::InvalidInput);
    };
    binding.validate().map_err(|_| StoreError::StoreCorrupt)?;
    let id = binding.work_binding_revision_id.to_string();
    if row.object_kind.as_deref() != Some("work_binding")
        || row.object_id.as_ref() != Some(&id)
        || row.current_revision_id.as_ref() != Some(&id)
        || row.row_id != format!("object:work:work_binding:{id}")
        || binding.assignment_status != evertrace_domain::work::AssignmentStatus::Resolved
    {
        return Err(StoreError::StoreCorrupt);
    }
    let mut source = object_identifier_row(
        row,
        &payload,
        true,
        vec!["assignment:resolved".into()],
        0,
        row.source_event_seq,
    )?;
    source.lifecycle = Some("active".into());
    Ok(source)
}

/// Use the same bounded text and revision ID as the indexed physical object.
pub fn canonical_physical_source(
    row: &crate::ObjectRow,
) -> Result<SearchProjectionRow, StoreError> {
    if !matches!(
        row.object_kind.as_deref(),
        Some("operation" | "scope_effect")
    ) {
        return Err(StoreError::InvalidInput);
    }
    exact_identifier_row(row, row.source_event_seq, true)?.ok_or(StoreError::StoreCorrupt)
}

/// A frozen lineage operand is exact-only; descriptive metadata does not grant verification authority.
pub fn canonical_lineage_source(
    row: &crate::ObjectRow,
    repository: evertrace_domain::ids::RepositoryId,
    is_current: bool,
) -> Result<SearchProjectionRow, StoreError> {
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let (text, worktree) = match &payload {
        JournalPayload::WorktreeTransitionRecorded(transition) if transition.validate().is_ok() => (
            serde_json::json!({"kind":transition.kind,"lineage_assessment":transition.lineage_assessment}).to_string(), None,
        ),
        JournalPayload::WorktreeSnapshotRecorded(snapshot) if snapshot.validate().is_ok() => (
            serde_json::json!({"capture_status":snapshot.capture_status}).to_string(), Some(snapshot.worktree_instance_id),
        ),
        _ => return Err(StoreError::StoreCorrupt),
    };
    let mut source = object_identifier_row(
        row,
        &payload,
        is_current,
        vec![text],
        0,
        row.source_event_seq,
    )?;
    source.repository_id = Some(repository.to_string());
    source.worktree_id = worktree.map(|id| id.to_string());
    Ok(source)
}

/// Structured canonical Work sources are request-local, never an open-Episode FTS row.
pub fn canonical_work_episode_source(
    row: &crate::ObjectRow,
    is_current: bool,
) -> Result<SearchProjectionRow, StoreError> {
    row.validate()?;
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let JournalPayload::WorkEpisodeRecorded(episode) = &payload else {
        return Err(StoreError::InvalidInput);
    };
    episode.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if row.object_kind.as_deref() != Some("work_episode")
        || row.object_id.as_deref() != Some(episode.episode_id.to_string().as_str())
        || row.current_revision_id.as_deref() != Some(episode.revision_id.to_string().as_str())
        || row.row_id != format!("object:work:work_episode:{}", episode.revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    let mut fields = vec![
        episode.phase_contract.local_goal.clone(),
        episode.phase_contract.phase_label.clone(),
        episode.phase_contract.acceptance_boundary.clone(),
        episode.phase_contract.expected_state_transition.clone(),
    ];
    fields.extend(episode.phase_contract.primary_targets.iter().cloned());
    fields.extend(episode.open_loops.iter().cloned());
    fields.extend(episode.completed_outcome_refs.iter().cloned());
    object_identifier_row(row, &payload, is_current, fields, 0, row.source_event_seq)
}

pub(super) fn closed_episode_search_row(
    row: &crate::ObjectRow,
    episode: &evertrace_domain::work::WorkEpisode,
    digests: &[&SemanticDigest],
    is_current: bool,
) -> Result<SearchProjectionRow, StoreError> {
    if episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Closed {
        return Err(StoreError::InvalidInput);
    }
    let mut source = canonical_work_episode_source(row, is_current)?;
    let mut fields = vec![
        episode.phase_contract.local_goal.clone(),
        episode.phase_contract.phase_label.clone(),
    ];
    for digest in digests {
        digest.validate().map_err(|_| StoreError::StoreCorrupt)?;
        if digest.episode_id != Some(episode.episode_id)
            || digest.to_watermark > episode.semantic_watermark
            || !episode
                .semantic_digest_refs
                .contains(&digest.semantic_digest_id.to_string())
        {
            return Err(StoreError::StoreCorrupt);
        }
        if digest.status == SemanticDigestStatus::RejectedInvalid {
            continue;
        }
        fields.push(format!("digest:{}", digest.semantic_digest_id));
        let application = &digest.application;
        for values in [
            &application.progress_delta,
            &application.decision_delta,
            &application.outcome_delta,
            &application.failed_routes,
            &application.resolved_items,
            &application.open_loops,
        ] {
            for delta in values {
                fields.push(format!("{}: {}", delta.label, delta.value));
                fields.extend(delta.direct_refs.iter().cloned());
            }
        }
        fields.extend(digest.selected_direct_refs.iter().cloned());
    }
    fields.push(episode.phase_contract.acceptance_boundary.clone());
    fields.push(episode.phase_contract.expected_state_transition.clone());
    for values in [
        &episode.phase_contract.primary_targets,
        &episode.open_loops,
        &episode.failure_refs,
        &episode.interruption_refs,
        &episode.completed_outcome_refs,
        &episode.selected_outcome_refs,
        &episode.verification_refs,
    ] {
        fields.extend(values.iter().cloned());
    }
    source.text = bounded_search_text(&episode.episode_id.to_string(), &fields);
    source.source_sequence = episode.source_watermark;
    source.time_domain = "source_sequence".into();
    source.validate()?;
    Ok(source)
}

fn object_identifier_row(
    row: &crate::ObjectRow,
    payload: &JournalPayload,
    is_current: bool,
    semantic: Vec<String>,
    event_time_us: i64,
    source_event_seq: u64,
) -> Result<SearchProjectionRow, StoreError> {
    let id = row.object_id.as_ref().ok_or(StoreError::StoreCorrupt)?;
    let text = bounded_search_text(id, &semantic);
    let source_ref = id.clone();
    let (repository_id, worktree_id) = match payload {
        JournalPayload::ScopeEffectDerived(value) => (
            value.repository_instance_id.map(|id| id.to_string()),
            value.worktree_instance_id.map(|id| id.to_string()),
        ),
        JournalPayload::RevisionProposalRecorded(proposal) => match &proposal.payload {
            evertrace_domain::semantic::ProposalPayload::Procedure(value) => {
                match value.draft().scope {
                    evertrace_domain::procedure::ProcedureScope::Repository { repository_id } => {
                        (Some(repository_id.to_string()), None)
                    }
                    evertrace_domain::procedure::ProcedureScope::Worktree {
                        repository_id,
                        worktree_id,
                    } => (
                        Some(repository_id.to_string()),
                        Some(worktree_id.to_string()),
                    ),
                    evertrace_domain::procedure::ProcedureScope::Global => (None, None),
                }
            }
            _ => (None, None),
        },
        _ => (row.repository_id.clone(), row.worktree_id.clone()),
    };
    Ok(SearchProjectionRow {
        row_id: format!("search:object:{}", row.row_id),
        row_variant: "object".into(),
        candidate_id: Some(
            row.current_revision_id
                .clone()
                .unwrap_or_else(|| id.clone()),
        ),
        source_ref: Some(source_ref),
        source_kind: Some("object_projection".into()),
        text,
        source_role: None,
        content_trust: None,
        capture_completeness: None,
        instruction_authority: "none".into(),
        object_kind: row.object_kind.clone(),
        currentness: Some(if is_current { "current" } else { "historical" }.into()),
        lifecycle: Some(normalized_lifecycle(row.lifecycle.as_deref()).into()),
        epistemic: if matches!(payload, JournalPayload::RevisionProposalRecorded(_)) {
            Some("unverified".into())
        } else {
            row.epistemic.clone()
        },
        authority: if matches!(payload, JournalPayload::RevisionProposalRecorded(_)) {
            Some("agent_inferred".into())
        } else {
            row.authority.clone()
        },
        task_id: row.task_id.clone(),
        repository_id,
        worktree_id,
        event_time_us,
        recorded_at_us: 0,
        source_sequence: 0,
        time_domain: if event_time_us > 0 {
            "event_time".into()
        } else {
            "none".into()
        },
        retrieval_completeness: "complete".into(),
        suppression_ref_hash: None,
        source_event_seq,
        projection_generation: SEARCH_PROJECTION_GENERATION,
    })
}

fn allowlisted_object_text(
    payload: &JournalPayload,
    max_text_bytes: usize,
) -> Option<(Vec<String>, i64)> {
    match payload {
        JournalPayload::AtomRecorded(value) => {
            let mut text = vec![
                value.value.text.clone(),
                value.value.subject.clone(),
                value.value.predicate.clone(),
            ];
            text.extend(value.value.object.clone());
            for qualifier in &value.value.qualifiers {
                text.push(qualifier.name.clone());
                text.push(qualifier.value.clone());
            }
            Some((text, value.created_at_us))
        }
        JournalPayload::TaskRecorded(value) => {
            Some((vec![value.canonical_goal.clone()], value.created_at_us))
        }
        JournalPayload::WorkstreamRecorded(value) => Some((
            vec![
                value.root_goal.clone(),
                value.workstream_goal.clone(),
                value.target_family.clone(),
                value.hypothesis_or_failure_family.clone(),
                value.acceptance_boundary.clone(),
            ],
            0,
        )),
        JournalPayload::AttemptRecorded(value) => Some((
            vec![
                value.strategy_contract.hypothesis.clone(),
                value.strategy_contract.intervention.clone(),
                value.strategy_contract.intervention_family.clone(),
                value.strategy_contract.expected_effect.clone(),
                value.failure_signature.clone().unwrap_or_default(),
            ],
            0,
        )),
        JournalPayload::ExperimentRunRecorded(value) => Some((
            safe_experiment_fields(
                &value.metric_definition,
                &value.data_fingerprint,
                &value.environment_fingerprint,
            ),
            value.created_at_us,
        )),
        JournalPayload::OperationDerived(value) => Some((
            vec![serde_json::json!({
                "operation_kind": value.operation_kind,
                "pairing_state": value.pairing_state,
                "source_local_pairing": value.source_local_pairing.as_ref().map(|pairing| &pairing.state),
            })
            .to_string()],
            0,
        )),
        JournalPayload::ScopeEffectDerived(value) => Some((
            vec![serde_json::json!({
                "effect_role": value.effect_role,
                "operation_id": value.operation_id,
            })
            .to_string()],
            0,
        )),
        JournalPayload::ResultEvidenceRecorded(value) => Some((Vec::new(), value.created_at_us)),
        JournalPayload::WorkArtifactRecorded(value) => Some((
            safe_artifact_fields(&value.revision.logical_name, &value.revision.media_type),
            value.revision.created_at_us,
        )),
        JournalPayload::ScenarioRecorded(value) => {
            let mut text = vec![value.goal.clone()];
            text.extend(value.current_state.iter().cloned());
            text.extend(value.open_loops.iter().cloned());
            text.extend(value.completed_outcomes.iter().cloned());
            Some((text, 0))
        }
        JournalPayload::SemanticDigestRecorded(value) => {
            let mut text = Vec::new();
            for delta in [
                &value.application.progress_delta,
                &value.application.decision_delta,
                &value.application.failed_routes,
                &value.application.resolved_items,
                &value.application.open_loops,
                &value.application.outcome_delta,
            ] {
                for item in delta {
                    text.push(item.label.clone());
                    text.push(item.value.clone());
                }
            }
            Some((text, value.created_at_us))
        }
        JournalPayload::ProcedureRevisionRecorded(value) => {
            Some((value.route_text_fields(max_text_bytes), value.created_at_us))
        }
        JournalPayload::RevisionProposalRecorded(value) => {
            let evertrace_domain::semantic::ProposalPayload::Procedure(payload) = &value.payload
            else {
                return None;
            };
            let draft = payload.draft();
            let mut text = vec![
                "Unaccepted method hypothesis; effectiveness unverified.".into(),
                draft.title.clone(),
                draft.summary.clone(),
            ];
            text.extend(draft.when.goals.clone());
            text.extend(draft.when.requires.clone());
            text.extend(draft.actions.stages.clone());
            text.extend(draft.done.verify.clone());
            text.extend(draft.pitfalls.clone());
            text.extend(draft.evidence_refs.clone());
            Some((text, value.created_at_us))
        }
        JournalPayload::CoreMembershipRecorded(_)
        | JournalPayload::GlobalSupportContractRecorded(_)
        | JournalPayload::GlobalSupportValidationRecorded(_) => Some((Vec::new(), 0)),
        _ => None,
    }
}

fn safe_experiment_fields(
    metric_definition: &str,
    data_fingerprint: &str,
    environment_fingerprint: &str,
) -> Vec<String> {
    vec![
        metric_definition.into(),
        data_fingerprint.into(),
        environment_fingerprint.into(),
    ]
}

fn safe_artifact_fields(logical_name: &str, media_type: &str) -> Vec<String> {
    vec![logical_name.into(), media_type.into()]
}

fn bounded_search_text(identifier: &str, values: &[String]) -> String {
    let mut output = identifier.to_owned();
    for value in values.iter().filter(|value| !value.is_empty()) {
        if output.len() + value.len() + 1 > 8 * 1024 {
            break;
        }
        output.push(' ');
        output.push_str(value);
    }
    output
}

fn normalized_lifecycle(value: Option<&str>) -> &'static str {
    match value {
        Some(
            "closed" | "completed" | "failed" | "abandoned" | "interrupted" | "superseded"
            | "deprecated" | "removed" | "accepted" | "rejected" | "expired",
        ) => "terminal",
        Some(_) => "active",
        None => "unknown",
    }
}

pub(super) fn surface_row(
    surface: &EvidenceSurface,
    receipt: &SourceReceipt,
    seq: u64,
) -> Result<SearchProjectionRow, StoreError> {
    surface.validate().map_err(|_| StoreError::StoreCorrupt)?;
    receipt.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if receipt.source_observation_id != surface.source_observation_revision_ref {
        return Err(StoreError::StoreCorrupt);
    }
    let suppression = default_retrieval_suppression_ref_hash(
        surface,
        receipt,
        DefaultRetrievalSuppressionGeneration::ContentSpanV2,
    )?;
    Ok(SearchProjectionRow {
        row_id: format!(
            "search:evidence:{}:{}",
            surface.source_observation_revision_ref, surface.span_hash
        ),
        row_variant: "evidence_surface".into(),
        candidate_id: Some(surface.candidate_ref()),
        source_ref: Some(surface.source_observation_revision_ref.to_string()),
        source_kind: Some("evidence_surface".into()),
        text: surface.protected_text.clone(),
        source_role: Some(
            serde_json::to_string(&surface.source_role)
                .map_err(|_| StoreError::StoreCorrupt)?
                .trim_matches('"')
                .into(),
        ),
        content_trust: Some(
            serde_json::to_string(&surface.content_trust)
                .map_err(|_| StoreError::StoreCorrupt)?
                .trim_matches('"')
                .into(),
        ),
        capture_completeness: Some(
            serde_json::to_string(&surface.capture_completeness)
                .map_err(|_| StoreError::StoreCorrupt)?
                .trim_matches('"')
                .into(),
        ),
        instruction_authority: "none".into(),
        object_kind: None,
        currentness: None,
        lifecycle: None,
        epistemic: None,
        authority: None,
        task_id: surface.task_id.map(|id| id.to_string()),
        repository_id: surface.repository_instance_id.map(|id| id.to_string()),
        worktree_id: surface.worktree_instance_id.map(|id| id.to_string()),
        event_time_us: surface.event_time_us,
        recorded_at_us: surface.recorded_at_us,
        source_sequence: surface.source_sequence,
        time_domain: if surface.event_time_us > 0 {
            "event_time".into()
        } else {
            "source_sequence".into()
        },
        retrieval_completeness: if matches!(
            surface.capture_completeness,
            evertrace_domain::evidence::CaptureCompleteness::Complete
        ) {
            "complete".into()
        } else {
            "partial".into()
        },
        suppression_ref_hash: Some(suppression),
        source_event_seq: seq,
        projection_generation: SEARCH_PROJECTION_GENERATION,
    })
}

fn source_kind(kind: EvidenceSourceKind) -> &'static str {
    match kind {
        EvidenceSourceKind::CodexHook => "codex_hook",
        EvidenceSourceKind::CodexExecJsonl => "codex_exec_jsonl",
        EvidenceSourceKind::CodexSessionJsonl => "codex_session_jsonl",
        EvidenceSourceKind::HermesSession => "hermes_session",
        EvidenceSourceKind::Other => "other",
    }
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::{
        ids::{ExperimentRunId, SourceReceiptId, WorkstreamId, WorktreeSnapshotId},
        revision::RevisionId,
        work::{
            AttemptBindingStatus, ExperimentRun, MultiCasMetricPolicy, RunContractValidity,
            RunExecutionStatus, RunObservability, RunOrigin, SeedPolicy, VariableDeclaration,
        },
    };

    use super::*;

    #[test]
    fn external_keys_references_and_debug_metrics_are_not_search_text() {
        let secret = "S19_SECRET_CANARY_bearer_token";
        let experiment = bounded_search_text(
            "01890f47-6a4a-7cc1-98b9-01890f476e00",
            &safe_experiment_fields("metric", "data", "environment"),
        );
        let artifact = bounded_search_text(
            "01890f47-6a4a-7cc1-98b9-01890f476e01",
            &safe_artifact_fields("report", "text/plain"),
        );
        assert!(!experiment.contains(secret));
        assert!(!artifact.contains(secret));
        assert!(!experiment.contains("ParsedMetric"));
        assert!(!artifact.contains("ParsedMetric"));

        let mut run = ExperimentRun {
            run_id: ExperimentRunId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            workstream_id: WorkstreamId::new_v7(),
            attempt_id: None,
            attempt_binding_status: AttemptBindingStatus::Unresolved,
            strategy_contract_fingerprint: [0x19; 32],
            origin: RunOrigin::External,
            external_system_id: Some("external-runner".into()),
            external_run_key: Some(secret.into()),
            source_receipt_refs: vec![
                SourceReceiptId::from_str(&format!("src:{}", "19".repeat(32))).unwrap(),
            ],
            observability: RunObservability::Declared,
            execution_status: RunExecutionStatus::Unknown,
            contract_validity: RunContractValidity::Unknown,
            experiment_contract_fingerprint: [0; 32],
            code_snapshot_id: WorktreeSnapshotId::new_v7(),
            data_fingerprint: "safe-data".into(),
            normalized_config: Vec::new(),
            variable_declaration: VariableDeclaration {
                varied: Vec::new(),
                fixed: Vec::new(),
                uncontrolled: Vec::new(),
            },
            comparison_key: [0; 32],
            seed_policy: SeedPolicy::Fixed,
            seed_values: vec!["7".into()],
            nondeterministic: false,
            metric_definition: "safe-metric".into(),
            metric_extractor_version: "safe-parser-v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: "safe-environment".into(),
            comparison_execution_binding: None,
            work_artifact_refs: Vec::new(),
            terminal_evidence_refs: Vec::new(),
            created_at_us: 19,
            started_at_us: None,
            ended_at_us: None,
        };
        run.experiment_contract_fingerprint = run.recompute_exact_contract_fingerprint().unwrap();
        run.comparison_key = run.recompute_comparison_key().unwrap();
        run.validate().unwrap();
        let run_id = run.run_id.to_string();
        let revision_id = run.revision_id.to_string();
        let object = crate::ObjectRow {
            row_id: format!("experiment_run:{run_id}"),
            row_kind: crate::ObjectRowKind::Data,
            row_class: Some(crate::ObjectRowClass::Object),
            object_family: Some(crate::ObjectFamily::Work),
            object_kind: Some("experiment_run".into()),
            object_id: Some(run_id),
            current_revision_id: Some(revision_id),
            lifecycle: Some("unknown".into()),
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: Some(run.workstream_id.to_string()),
            session_id: None,
            payload_json: Some(
                serde_json::to_string(&JournalPayload::ExperimentRunRecorded(Box::new(run)))
                    .unwrap()
                    .into(),
            ),
            source_event_seq: 19,
            projection_generation: 1,
        };
        let projected = exact_identifier_row(&object, 19, true).unwrap().unwrap();
        assert!(!projected.text.contains(secret));
        assert!(projected.text.contains("safe-metric"));
    }
}
