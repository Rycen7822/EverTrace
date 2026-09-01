mod explorer;
mod inbox;
mod system;
use crate::{AppState, Route};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    match state.route {
        Route::Inbox => inbox::render(f, a, state),
        Route::Explorer => explorer::render(f, a, state),
        Route::System => system::render(f, a, state),
    }
}

pub(super) fn snapshot_rows(state: &AppState, empty: &str) -> String {
    use evertrace_protocol::dto::HumanGovernanceResponse;
    match state.human.as_ref() {
        Some(HumanGovernanceResponse::Snapshot {
            frontier,
            status,
            degraded_reasons,
            items,
            next_cursor,
        }) => {
            let mut lines = vec![format!(
                "frontier:{frontier} status:{status:?}{}{}",
                if next_cursor.is_some() { " more" } else { "" },
                if degraded_reasons.is_empty() {
                    String::new()
                } else {
                    format!(" reasons:{degraded_reasons:?}")
                }
            )];
            lines.extend(items.iter().enumerate().map(|(index, item)| {
                format!(
                    "{} {}  {}  {}",
                    if index == state.selection { ">" } else { " " },
                    category_label(item.category),
                    item.object_ref.as_deref().unwrap_or("-"),
                    item.lifecycle
                        .as_deref()
                        .or(item.publication_state.as_deref())
                        .or(item.support_state.as_deref())
                        .unwrap_or("current")
                )
            }));
            if let Some(result) = &state.last_action {
                lines.push(format!(
                    "action: {:?} {}",
                    result.status,
                    result.reason.as_deref().unwrap_or("")
                ));
            }
            lines.join("\n")
        }
        Some(HumanGovernanceResponse::Conflict {
            current_frontier,
            current_revision_ref,
        }) => {
            format!(
                "optimistic conflict; reload frontier {current_frontier}{}",
                current_revision_ref
                    .as_deref()
                    .map_or(String::new(), |revision| format!(" revision {revision}"))
            )
        }
        Some(HumanGovernanceResponse::Action { result }) => format!(
            "action: {:?} {}",
            result.status,
            result.reason.as_deref().unwrap_or("")
        ),
        None => match state.shell.connection {
            crate::ConnectionState::Connecting => empty.into(),
            crate::ConnectionState::Disconnected => "Daemon disconnected".into(),
            crate::ConnectionState::ServerStopping => "Daemon stopping; read unavailable".into(),
            crate::ConnectionState::Connected => state.read_conflict.map_or_else(
                || empty.into(),
                |frontier| format!("optimistic conflict; reload frontier {frontier}"),
            ),
        },
    }
}

pub(super) fn page_body(state: &AppState, empty: &str) -> String {
    if state.detail.is_some() || state.detail_message.is_some() {
        inspector_text(state)
    } else {
        snapshot_rows(state, empty)
    }
}

pub(crate) fn inspector_text(state: &AppState) -> String {
    if let Some(message) = &state.detail_message {
        return format!("Detail\n{message}\nEsc returns to list");
    }
    let item = state.detail.as_ref().or_else(|| {
        let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { items, .. } =
            state.human.as_ref()?
        else {
            return None;
        };
        items.get(state.selection)
    });
    let Some(item) = item else {
        return "Select an item".into();
    };
    let (frontier, daemon_status) = match state.human.as_ref() {
        Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
            frontier,
            status,
            degraded_reasons,
            ..
        }) => (
            Some(*frontier),
            format!("daemon: {status:?} {degraded_reasons:?}"),
        ),
        _ => (None, "daemon: unavailable".into()),
    };
    let mut lines = vec![
        format!("{} / {}", category_label(item.category), item.object_kind),
        format!(
            "projection frontier: {}",
            frontier.map_or_else(|| "-".into(), |value| value.to_string())
        ),
        format!("family: {:?}  class: {:?}", item.family, item.row_class),
        format!("object: {}", item.object_ref.as_deref().unwrap_or("-")),
        format!("revision: {}", item.revision_ref.as_deref().unwrap_or("-")),
        format!("lifecycle: {}", item.lifecycle.as_deref().unwrap_or("-")),
        format!("epistemic: {}", item.epistemic.as_deref().unwrap_or("-")),
        format!("authority: {}", item.authority.as_deref().unwrap_or("-")),
        format!(
            "publication/support: {}/{}",
            item.publication_state.as_deref().unwrap_or("-"),
            item.support_state.as_deref().unwrap_or("-")
        ),
        format!("scope: {}", item.scope_ref.as_deref().unwrap_or("-")),
        format!("source event: {}", item.source_event_seq),
        format!("audit row: {}", item.stable_key),
        daemon_status,
    ];
    if let Some(proposal) = &item.proposal {
        lines.extend([
            format!(
                "target: {:?} {:?}",
                proposal.target_kind, proposal.target_id
            ),
            format!(
                "operation/base: {:?} {}",
                proposal.operation,
                proposal
                    .base_revision_id
                    .map_or_else(|| "-".into(), |value| value.to_string())
            ),
            format!(
                "eligibility/status: {:?}/{:?}",
                proposal.eligibility, proposal.status
            ),
            format!("fingerprint: {}", proposal.fingerprint),
            format!(
                "source cohort ({}): {}",
                proposal.source_cohort_refs.len(),
                proposal
                    .source_cohort_refs
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ]);
    }
    if let Some(review) = &item.proposal_review {
        lines.extend([
            format!("plain accept eligible: {}", review.plain_accept_eligible),
            format!(
                "merge-and-accept eligible: {}",
                review.merge_and_accept_eligible
            ),
            format!("created by: {:?}", review.proposal.created_by),
            format!("proposal evidence: {:?}", review.proposal.evidence_refs),
            format!("review payload:\n{:#?}", review.proposal.payload),
        ]);
        lines.push("edit-and-accept: unavailable".into());
        if let Some(reference) = &review.reauthorization {
            lines.extend([
                "re-authorize forgotten object: available".into(),
                format!("forgotten target: {:?}", reference.target),
                format!("deletion generation: {}", reference.deletion_generation),
                format!("purge audit ref: {}", reference.purge_job_audit_ref),
                "R re-authorize forgotten object".into(),
            ]);
        }
    }
    if let Some(support) = &item.support_detail {
        lines.extend([
            format!(
                "support contract/validation: {} / {}",
                support.support_contract_revision_id, support.validation_revision_id
            ),
            format!("support successor: {}", support.successor_ref),
            format!(
                "support state/generation: {:?} / {}",
                support.state, support.dependency_generation
            ),
            format!(
                "threshold: minimum={} authorization={} degraded={}",
                support.threshold.minimum_surviving_support,
                support.threshold.require_authorization,
                support.provenance_degraded
            ),
            format!("support refs: {:?}", support.support_revision_refs),
            format!(
                "authorization refs: {:?}",
                support.authorization_revision_refs
            ),
            format!("surviving refs: {:?}", support.surviving_support_refs),
            format!(
                "invalid/missing refs: {:?}",
                support.invalid_or_missing_refs
            ),
            format!("trigger refs: {:?}", support.trigger_refs),
        ]);
    }
    if let Some(detail) = &item.competing_detail {
        let selected = detail
            .eligible_attempt_ids
            .get(state.competing_candidate_selection)
            .map_or_else(|| "-".into(), ToString::to_string);
        lines.extend([
            format!("competing revision: {}", detail.expected_group_revision_id),
            format!("eligible attempts: {:?}", detail.eligible_attempt_ids),
            format!("selected winner: {selected}"),
            "[/] choose; c stages selected winner; Enter confirms; Esc cancels".into(),
        ]);
    }
    if let Some(preview) = &item.forget_preview {
        lines.extend([
            format!("forget target: {:?}", preview.target),
            format!("current revision: {}", preview.current_revision_id),
            format!(
                "closure: {} revision(s), deletion generation {}",
                preview.exact_revision_ids.len(),
                preview.deletion_generation
            ),
            format!(
                "sources: {} shared retained, {} source(s) / {} span key(s) suppressed",
                preview.shared_source_count,
                preview.suppressed_source_count,
                preview.suppression_ref_count
            ),
            format!(
                "dependency fence: {} support revalidation, {} procedure review-hold",
                preview.downstream_support_revalidation_count,
                preview.dependent_procedure_review_hold_count
            ),
            "Shared source/Evidence is retained by default; this is not source erasure.".into(),
            "F stages human-only Forget; Enter confirms once; Esc cancels".into(),
        ]);
    }
    if let Some(review) = &item.negative_review {
        lines.extend([
            format!("negative evidence: {}", review.negative_evidence_id),
            format!(
                "review revision/status: {} / {:?}",
                review.current_review_revision_id, review.status
            ),
            format!("available decisions: {:?}", review.available_decisions),
        ]);
    }
    if let Some(detail) = &item.recovery_detail {
        use evertrace_protocol::dto::HumanRecoveryDetail;
        match detail {
            HumanRecoveryDetail::CaptureRequest {
                request_id,
                revision_id,
                repository_id,
                worktree_id,
                destructive_class,
                untracked_scope,
                status,
                bundle_id,
                reason_codes,
            } => lines.extend([
                format!("request/revision: {request_id} / {revision_id}"),
                format!("repository/worktree: {repository_id} / {worktree_id}"),
                format!("destructive/untracked: {destructive_class:?} / {untracked_scope:?}"),
                format!("request status: {status:?}"),
                format!(
                    "bundle: {}",
                    bundle_id.map_or_else(|| "-".into(), |value| value.to_string())
                ),
                format!("reason codes: {reason_codes:?}"),
            ]),
            HumanRecoveryDetail::Bundle {
                bundle_id,
                source_worktree_id,
                source_snapshot_id,
                capture_status,
                ordering_integrity,
                captured_bytes,
                tracked_diff_count,
                tracked_file_count,
                index_state_count,
                untracked_file_count,
                untracked_artifact_count,
                metadata_artifact_count,
                config_run_count,
                attempt_anchor_count,
                omission_counts,
            } => lines.extend([
                format!("bundle: {bundle_id}"),
                format!("source worktree/snapshot: {source_worktree_id} / {source_snapshot_id}"),
                format!("capture/order: {capture_status:?} / {ordering_integrity:?}"),
                format!("captured bytes: {captured_bytes}"),
                format!(
                    "content counts: diff {tracked_diff_count}, files {tracked_file_count}, index {index_state_count}, untracked {untracked_file_count}, artifacts {untracked_artifact_count}, metadata {metadata_artifact_count}, config/run {config_run_count}"
                ),
                format!("attempt anchors: {attempt_anchor_count}"),
                format!("omissions: {omission_counts:?}"),
            ]),
            HumanRecoveryDetail::Application {
                application_id,
                revision_id,
                bundle_id,
                target_worktree_id,
                application_kind,
                input_delivery_state,
                status,
                pre_snapshot_id,
                post_snapshot_id,
                selected_input_count,
                result_count,
                verifier_count,
            } => lines.extend([
                format!("application/revision: {application_id} / {revision_id}"),
                format!("bundle/target: {bundle_id} / {target_worktree_id}"),
                format!("kind/delivery/status: {application_kind:?} / {input_delivery_state:?} / {status:?}"),
                format!(
                    "pre/post snapshot: {pre_snapshot_id} / {}",
                    post_snapshot_id.map_or_else(|| "-".into(), |value| value.to_string())
                ),
                format!("selected inputs/results/verifiers: {selected_input_count}/{result_count}/{verifier_count}"),
            ]),
        }
    }
    if let Some(detail) = &item.worktree_detail {
        lines.extend([
            format!(
                "worktree/repository: {} / {}",
                detail.worktree_id, detail.repository_id
            ),
            format!("kind/lifecycle: {:?} / {:?}", detail.kind, detail.lifecycle),
            format!("registration: {:?}", detail.registration_state),
            format!(
                "current snapshot: {}",
                detail
                    .current_snapshot_id
                    .map_or_else(|| "-".into(), |value| value.to_string())
            ),
        ]);
    }
    if let Some(detail) = &item.execution_integrity_detail {
        use evertrace_protocol::dto::HumanExecutionIntegrityDetail;
        match detail {
            HumanExecutionIntegrityDetail::Lane {
                execution_lane_id,
                lane_revision,
                parent_lane_id,
                status,
                terminal_kind,
                liveness_state,
                finalized,
                event_watermark,
                active_capture_receipt_revision_id,
                coverage_level,
                source_coverage,
                pairing_integrity,
                payload_integrity,
                ordering_integrity,
                reasoning_visibility,
            } => lines.extend([
                format!("lane/revision: {execution_lane_id} / {lane_revision}"),
                format!(
                    "parent lane: {}",
                    parent_lane_id.map_or_else(|| "-".into(), |value| value.to_string())
                ),
                format!("status/terminal/liveness: {status:?} / {terminal_kind:?} / {liveness_state:?}"),
                format!("finalized/watermark: {finalized} / {event_watermark}"),
                format!("active receipt: {active_capture_receipt_revision_id}"),
                format!("coverage/source: {coverage_level:?} / {source_coverage:?}"),
                format!("pairing/payload/order: {pairing_integrity:?} / {payload_integrity:?} / {ordering_integrity:?}"),
                format!("reasoning visibility: {reasoning_visibility:?}"),
            ]),
            HumanExecutionIntegrityDetail::Receipt {
                capture_receipt_revision_id,
                execution_lane_id,
                predecessor_revision_id,
                admission_failure_observability,
                identity_strength,
                delegation_start_seen,
                child_session_linked,
                parent_session_end_seen,
                lifecycle_end_seen,
                terminal_event_kind,
                finalized,
                first_sequence,
                last_sequence,
                sequence_gap_count,
                outage_count,
                tool_call_count,
                tool_result_count,
                unmatched_tool_call_count,
                unmatched_tool_result_count,
                truncation_count,
                redaction_count,
                corrupt_count,
                unsupported_count,
                import_watermark,
                coverage_level,
                source_coverage,
                pairing_integrity,
                payload_integrity,
                ordering_integrity,
                reasoning_visibility,
                exact_byte_replay,
                resolver_version,
            } => lines.extend([
                format!("receipt/lane: {capture_receipt_revision_id} / {execution_lane_id}"),
                format!("predecessor: {}", predecessor_revision_id.map_or_else(|| "-".into(), |value| value.to_string())),
                format!("admission/identity: {admission_failure_observability:?} / {identity_strength:?}"),
                format!("delegation/child/parent/lifecycle: {delegation_start_seen}/{child_session_linked}/{parent_session_end_seen}/{lifecycle_end_seen}"),
                format!("terminal/finalized: {terminal_event_kind:?} / {finalized}"),
                format!("sequence: {first_sequence:?}..{last_sequence:?}; gaps {sequence_gap_count}; outages {outage_count}"),
                format!("tool calls/results/unmatched: {tool_call_count}/{tool_result_count}/{unmatched_tool_call_count}/{unmatched_tool_result_count}"),
                format!("truncated/redacted/corrupt/unsupported: {truncation_count}/{redaction_count}/{corrupt_count}/{unsupported_count}"),
                format!("import watermark: {import_watermark}"),
                format!("coverage/source: {coverage_level:?} / {source_coverage:?}"),
                format!("pairing/payload/order: {pairing_integrity:?} / {payload_integrity:?} / {ordering_integrity:?}"),
                format!("reasoning visibility: {reasoning_visibility:?}"),
                format!("exact replay/resolver: {exact_byte_replay} / {resolver_version}"),
            ]),
        }
    }
    if let Some(detail) = &item.system_detail {
        use evertrace_protocol::dto::HumanSystemDetail;
        match detail {
            HumanSystemDetail::Job { detail } => lines.extend([
                format!("job: {}", detail.job_id),
                format!(
                    "target: {} @ {}/{}",
                    detail.target_revision, detail.target_watermark, detail.target_generation
                ),
                format!(
                    "kind/algorithm/model: {} / {} / {:?}",
                    detail.job_kind, detail.algorithm_revision, detail.model_id
                ),
                format!(
                    "priority/state/attempt: {} / {:?} / {}",
                    detail.priority, detail.state, detail.attempt
                ),
                format!(
                    "backoff/lease: {:?} / {:?}",
                    detail.backoff_until_us, detail.lease_until_us
                ),
                format!(
                    "config hash: {}",
                    evertrace_domain::evidence::hex(&detail.config_hash)
                ),
                format!(
                    "budget: items {} bytes {:?} input {:?} output {:?} calls {:?} wall {}ms",
                    detail.budget.max_items,
                    detail.budget.max_bytes,
                    detail.budget.max_input_tokens,
                    detail.budget.max_output_tokens,
                    detail.budget.max_calls,
                    detail.budget.max_wall_time_ms
                ),
                format!(
                    "terminal: {:?} / {:?}",
                    detail.terminal_reason, detail.terminal_result_ref
                ),
            ]),
            HumanSystemDetail::Config {
                config_version,
                effective_config_hash,
            } => lines.extend([
                format!("config version: {config_version}"),
                format!(
                    "effective config hash: {}",
                    evertrace_domain::evidence::hex(effective_config_hash)
                ),
            ]),
        }
    }
    if state.detail.is_some() {
        lines.push("Esc returns to list".into());
    } else {
        lines.push("Enter opens detail".into());
    }
    lines.join("\n")
}

fn category_label(category: evertrace_protocol::dto::HumanItemCategory) -> &'static str {
    use evertrace_protocol::dto::HumanItemCategory as Category;
    match category {
        Category::Proposal => "proposal",
        Category::Support => "support/revalidation",
        Category::NegativeReview => "negative review",
        Category::SegmentationCorrection => "segmentation correction",
        Category::RecoveryCorrection => "recovery correction",
        Category::Assignment => "work assignment",
        Category::CompetingResolution => "competing resolution",
        Category::AttemptResume => "attempt resume",
        Category::LaneLifecycle => "lane lifecycle",
        Category::CaptureIntegrity => "capture integrity",
        Category::WorktreeLineage => "worktree lineage",
        Category::ReviewHold => "review hold",
        Category::Repository => "repository lineage",
        Category::Work => "work execution",
        Category::Semantic => "semantic asset",
        Category::Procedure => "procedure",
        Category::Research => "experiment/artifact",
        Category::RecoveryEvidence => "recovery evidence",
        Category::Evidence => "evidence/provenance",
        Category::Runtime => "runtime status",
        Category::Projection => "derived projection",
        Category::SessionImport => "session import",
        Category::SemanticDerivation => "semantic derivation",
    }
}
