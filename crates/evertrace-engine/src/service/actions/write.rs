use super::*;

impl McpActionService {
    pub(super) async fn add(
        &self,
        request_id: RequestId,
        scope: McpRequestScope,
        input: String,
        refs: Vec<String>,
    ) -> Result<McpServiceResult, McpServiceError> {
        let anchor_task = scope.anchor.task_id;
        if refs.iter().any(|reference| {
            reference.starts_with("task:")
                && reference.parse::<evertrace_domain::ids::TaskId>().is_err()
        }) {
            return Ok(unresolved_add(request_id, &scope));
        }
        let ref_tasks = refs
            .iter()
            .filter(|reference| reference.starts_with("task:"))
            .map(|reference| reference.parse())
            .collect::<Result<BTreeSet<evertrace_domain::ids::TaskId>, _>>()
            .map_err(|_| McpServiceError::Store)?;
        let ref_task = (ref_tasks.len() == 1)
            .then(|| ref_tasks.iter().next().copied())
            .flatten();
        let task_id = match (anchor_task, ref_task, ref_tasks.is_empty()) {
            (Some(task), None, true) => task,
            (Some(task), Some(reference), false) if task == reference => task,
            (None, Some(reference), false) => reference,
            _ => return Ok(unresolved_add(request_id, &scope)),
        };
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| McpServiceError::Store)?;
        let task_ref = task_id.to_string();
        let mut task_rows = snapshot.rows.iter().filter(|row| {
            row.row_kind == ObjectRowKind::Data
                && row.object_kind.as_deref() == Some("task")
                && row.object_id.as_deref() == Some(task_ref.as_str())
                && row.lifecycle.as_deref() == Some("active")
        });
        let Some(task_row) = task_rows.next() else {
            return Ok(unresolved_add(request_id, &scope));
        };
        let task_payload = task_row
            .payload_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok());
        let JournalPayload::TaskRecorded(task) =
            task_payload.as_ref().ok_or(McpServiceError::Store)?
        else {
            return Err(McpServiceError::Store);
        };
        let scope_matches = task_membership_matches(
            &task.scope_memberships,
            scope.anchor.repository_id,
            scope.anchor.worktree_id,
        );
        if task_rows.next().is_some() || !scope_matches {
            return Ok(unresolved_add(request_id, &scope));
        }
        let event_time_us = unix_time_us_for_mcp();
        let sequence = u64::try_from(event_time_us).unwrap_or(u64::MAX);
        let record_key = request_id.to_string();
        let source_instance_text = format!("evertrace-mcp-{record_key}");
        let source_revision_text = format!("mcp-v1-{record_key}");
        let source_instance =
            SourceInstanceId::parse(&source_instance_text).map_err(|_| McpServiceError::Store)?;
        let source_revision =
            SourceRevision::parse(&source_revision_text).map_err(|_| McpServiceError::Store)?;
        let source_record_identity =
            SourceRecordIdentity::parse(&record_key).map_err(|_| McpServiceError::Store)?;
        let observation_id =
            source_observation_id(&source_instance, &source_revision, &source_record_identity)
                .map_err(|_| McpServiceError::Store)?;
        let (session_ref, turn_ref, tool_ref) = scope.binding.anchor.as_ref().map_or_else(
            || {
                (
                    format!("mcp-unanchored-{record_key}"),
                    None,
                    Some(record_key.clone()),
                )
            },
            |anchor| {
                (
                    anchor.session_id.clone(),
                    Some(anchor.turn_id.clone()),
                    Some(anchor.tool_use_id.clone()),
                )
            },
        );
        let capture = CaptureRecordInput {
            spool_record_id: Some(format!("mcp-{record_key}")),
            source_observation_id_hint: Some(observation_id.to_string()),
            source_instance_id: source_instance_text,
            source_revision: source_revision_text,
            source_record_identity: Some(record_key.clone()),
            identity_strength: Some(IdentityStrength::StableNative),
            source_kind: EvidenceSourceKind::Other,
            identity_domain: "evertrace-mcp-v1".into(),
            source_ref: format!("evertrace-mcp-{record_key}"),
            session_ref,
            turn_ref,
            tool_ref,
            source_sequence: sequence,
            source_sequence_origin: Some(sequence),
            task_id: Some(task_ref),
            repository_instance_id: scope.anchor.repository_id.map(|id| id.to_string()),
            worktree_instance_id: scope.anchor.worktree_id.map(|id| id.to_string()),
            source_byte_range: None,
            source_revision_mode: SourceRevisionMode::Append,
            previous_source_revision: None,
            close_watermark: Some(sequence),
            observation_role: ObservationRole::Result,
            correlation: HostCorrelationEvidence {
                occurrence_schema_version: 1,
                host_instance_id: None,
                host_trace_lineage_id: None,
                host_lane_key: None,
                canonical_event_family: None,
                native_request_id: None,
                physical_execution_ordinal: None,
                pairing_role: ObservationRole::Result,
                field_provenance: Vec::new(),
                adapter_manifest_ref: "evertrace-mcp-v1".into(),
                adapter_revision: 1,
                strong_gate_receipt_ref: None,
                admission: CorrelationAdmission::Unavailable,
                partial_correlation_ref: None,
                possible_duplicate_group_id: None,
            },
            scope_effect_claims: Vec::new(),
            lifecycle: None,
            unsupported_record_classification: None,
            source_role: SourceRole::Assistant,
            content_trust: ContentTrust::AgentClaim,
            capture_completeness: CaptureCompleteness::Complete,
            surface_eligible: input.len() <= evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES,
            adapter_revision: 1,
            adapter_manifest_ref: "evertrace-mcp-v1".into(),
            eligible_event_manifest_ref: "evertrace-mcp-add-v1".into(),
            parser_revision: 1,
            canonicalization_revision: 1,
            event_time_us: Some(event_time_us),
            raw_payload: input.into_bytes(),
        };
        let mut runtime = CaptureRuntime::open(self.runtime_snapshot.clone())
            .map_err(|_| McpServiceError::Store)?;
        let outcome = runtime
            .capture(capture)
            .map_err(|_| McpServiceError::Store)?;
        let CaptureOutcome::Durable { .. } = outcome else {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::Partial,
                &scope_label(&scope),
                "unknown",
                ["capture_degraded"],
            ));
        };
        drop(runtime);
        EvidenceIngestor::new(
            self.runtime_snapshot.clone(),
            self.writer.clone(),
            self.runtime_snapshot.effective_config_hash,
            "s20-mcp-v1",
        )
        .map_err(|_| McpServiceError::Store)?
        .drain_observations_once(&[observation_id])
        .await
        .map_err(|_| McpServiceError::Store)?;
        let details = serde_json::to_string(&AddResultDetails {
            authorization_status: "unverified",
            proposal_created: false,
        })
        .map_err(|_| McpServiceError::Store)?;
        Ok(McpServiceResult {
            request_id,
            status: McpServiceStatus::Ok,
            scope: scope_label(&scope),
            freshness: "current".into(),
            completeness: "l0_only".into(),
            items: vec![McpServiceItem {
                partition: McpItemPartition::Evidence,
                kind: "source_observation".into(),
                object_ref: Some(observation_id.to_string()),
                object_revision_ref: None,
                source_revision_ref: Some(source_revision.as_str().to_owned()),
                scope: Some(task_id.to_string()),
                applicability: None,
                authority: None,
                content_trust: ContentTrust::AgentClaim,
                capture_completeness: Some("complete".into()),
                instruction_authority: InstructionAuthority::None,
                text: Some(details),
            }],
            warnings: vec!["no_atom_emitted".into()],
            truncated: false,
            next_refs: Vec::new(),
        })
    }

    pub(super) async fn organize(
        &self,
        request_id: RequestId,
        scope: McpRequestScope,
        input: String,
        refs: Vec<String>,
    ) -> Result<McpServiceResult, McpServiceError> {
        let parsed: OrganizeInput = match serde_json::from_str::<OrganizeInput>(&input) {
            Ok(value)
                if value.v == 1
                    && serde_json::to_string(&value).ok().as_deref() == Some(input.as_str()) =>
            {
                value
            }
            _ => return Ok(invalid_organize(request_id, &scope, "noncanonical_input")),
        };
        if contains_protected_patch_key(&parsed.patch) {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::Conflict,
                &scope_label(&scope),
                "unknown",
                ["protected_patch_field"],
            ));
        }
        let operation = match parsed.op.as_str() {
            "create" => ProposalOperation::Create,
            "replace" => ProposalOperation::Replace,
            "merge" => ProposalOperation::Merge,
            "split" => ProposalOperation::Split,
            "deprecate" => ProposalOperation::Deprecate,
            "reclassify" => ProposalOperation::Reclassify,
            _ => {
                return Ok(invalid_organize(
                    request_id,
                    &scope,
                    "unsupported_operation",
                ));
            }
        };
        let (target_kind, target_id) = match organize_target(&parsed.target, operation) {
            Some(value) => value,
            None => return Ok(invalid_organize(request_id, &scope, "invalid_target")),
        };
        let base_revision_id = match parsed.expected_revision.as_deref() {
            Some(value) => match value.parse::<RevisionId>() {
                Ok(revision) => Some(revision),
                Err(_) => {
                    return Ok(invalid_organize(
                        request_id,
                        &scope,
                        "invalid_expected_revision",
                    ));
                }
            },
            None => None,
        };
        let result_target = parsed.target.clone();
        let payload = match proposal_payload(target_kind, operation, parsed.patch, parsed.reason) {
            Some(payload) => payload,
            None => return Ok(invalid_organize(request_id, &scope, "invalid_patch")),
        };
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| McpServiceError::Store)?;
        let view =
            SemanticCurrentView::from_snapshot(&snapshot).map_err(|_| McpServiceError::Store)?;
        let occurred_at_us = unix_time_us_for_mcp();
        let resolution = RevisionProposalService.submit(
            &view,
            ProposalCommandContext {
                command_id: CommandId::new_v7(),
                occurred_at_us,
                effective_config_hash: self.runtime_snapshot.effective_config_hash,
                algorithm_revision: "s20-mcp-v1".into(),
            },
            SubmitProposalRequest {
                target_kind,
                target_id,
                base_revision_id,
                operation,
                payload,
                evidence_refs: refs.clone(),
                source_cohort_refs: refs,
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        );
        let (proposal_id, proposal_revision_id, proposal_status) = match resolution {
            Ok(ProposalResolution::NoDelta) => {
                return Ok(McpServiceResult {
                    request_id,
                    status: McpServiceStatus::Ok,
                    scope: scope_label(&scope),
                    freshness: "current".into(),
                    completeness: "no_delta".into(),
                    items: Vec::new(),
                    warnings: vec!["proposal_no_delta".into()],
                    truncated: false,
                    next_refs: Vec::new(),
                });
            }
            Ok(ProposalResolution::Revision { value, command }) => {
                self.writer
                    .commit(command, occurred_at_us)
                    .await
                    .map_err(|_| McpServiceError::Store)?;
                (
                    value.proposal_id.to_string(),
                    value.proposal_revision_id.to_string(),
                    value.status.as_str(),
                )
            }
            Err(
                crate::semantic::SemanticServiceError::BaseConflict
                | crate::semantic::SemanticServiceError::ImmutableConflict,
            ) => {
                return Ok(empty_result(
                    request_id,
                    McpServiceStatus::Conflict,
                    &scope_label(&scope),
                    "unknown",
                    ["proposal_conflict"],
                ));
            }
            Err(_) => {
                return Ok(invalid_organize(request_id, &scope, "invalid_proposal"));
            }
        };
        let details = serde_json::to_string(&OrganizeResultDetails {
            target: &result_target,
            operation: operation.as_str(),
            status: proposal_status,
        })
        .map_err(|_| McpServiceError::Store)?;
        Ok(McpServiceResult {
            request_id,
            status: McpServiceStatus::Ok,
            scope: scope_label(&scope),
            freshness: "current".into(),
            completeness: "proposal_only".into(),
            items: vec![McpServiceItem {
                partition: McpItemPartition::Evidence,
                kind: "revision_proposal".into(),
                object_ref: Some(proposal_id),
                object_revision_ref: Some(proposal_revision_id),
                source_revision_ref: None,
                scope: scope.anchor.task_id.map(|id| id.to_string()),
                applicability: None,
                authority: Some("agent_inferred".into()),
                content_trust: ContentTrust::AgentClaim,
                capture_completeness: None,
                instruction_authority: InstructionAuthority::None,
                text: Some(details),
            }],
            warnings: vec!["manual_review_required".into()],
            truncated: false,
            next_refs: Vec::new(),
        })
    }
}
