use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{EvidenceSourceKind, EvidenceSurface, SourceReceipt},
};

use crate::{JournalPayload, StoreError, search::SearchProjectionRow};

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
    let text = bounded_search_text(id, &semantic);
    let source_ref = id.clone();
    Ok(Some(SearchProjectionRow {
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
        epistemic: row.epistemic.clone(),
        authority: row.authority.clone(),
        task_id: row.task_id.clone(),
        repository_id: row.repository_id.clone(),
        worktree_id: row.worktree_id.clone(),
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
        projection_generation: 1,
    }))
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
        JournalPayload::ProcedureRevisionRecorded(value) => {
            Some((value.route_text_fields(max_text_bytes), value.created_at_us))
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
    let suppression = sha256(
        "evertrace_default_retrieval_suppression_ref",
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(source_kind(receipt.source_kind).into()),
            CanonicalValue::String(receipt.identity_domain.clone()),
            CanonicalValue::String(receipt.source_record_identity.as_str().into()),
            CanonicalValue::Integer(i128::from(surface.canonicalization_version)),
            CanonicalValue::String(surface.span_hash.clone()),
        ]),
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    Ok(SearchProjectionRow {
        row_id: format!(
            "search:evidence:{}:{}",
            surface.source_observation_revision_ref, surface.span_hash
        ),
        row_variant: "evidence_surface".into(),
        candidate_id: Some(format!(
            "{}:{}:{}",
            surface.source_observation_revision_ref,
            surface.canonicalization_version,
            surface.span_hash
        )),
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
        suppression_ref_hash: Some(hex(suppression)),
        source_event_seq: seq,
        projection_generation: 1,
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
                    .unwrap(),
            ),
            source_event_seq: 19,
            projection_generation: 1,
        };
        let projected = exact_identifier_row(&object, 19, true).unwrap().unwrap();
        assert!(!projected.text.contains(secret));
        assert!(projected.text.contains("safe-metric"));
    }
}
