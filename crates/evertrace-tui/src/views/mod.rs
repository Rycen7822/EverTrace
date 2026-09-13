mod detail;
mod explorer;
mod inbox;
mod system;
use crate::{AppState, Route};
pub(crate) use detail::{detail_text, wrap_content};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    match state.route {
        Route::Inbox => inbox::render(f, a, state),
        Route::Explorer => explorer::render(f, a, state),
        Route::System => system::render(f, a, state),
    }
}

pub(crate) fn visible_indices(state: &AppState) -> Vec<usize> {
    let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { items, .. }) =
        &state.human
    else {
        return vec![];
    };
    let query = state.ui.filter.to_lowercase();
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            let kind = if state.route == Route::System {
                match state.ui.system_view {
                    crate::state::SystemView::Jobs | crate::state::SystemView::Overview => {
                        matches!(
                            item.system_detail,
                            Some(evertrace_protocol::dto::HumanSystemDetail::Job { .. })
                        )
                    }
                    _ => true,
                }
            } else {
                true
            };
            kind && state
                .ui
                .type_filter
                .as_ref()
                .is_none_or(|v| v == &item.object_kind)
                && state
                    .ui
                    .scope_filter
                    .as_ref()
                    .is_none_or(|v| Some(v) == item.scope_ref.as_ref())
                && state
                    .ui
                    .state_filter
                    .as_ref()
                    .is_none_or(|v| v == &item_state(item))
                && row_label(item).to_lowercase().contains(&query)
        })
        .map(|(i, _)| i)
        .collect()
}
pub(crate) fn item_state(item: &evertrace_protocol::dto::HumanSnapshotItem) -> String {
    if let Some(evertrace_protocol::dto::HumanSystemDetail::Job { detail }) = &item.system_detail {
        format!("{:?}", detail.state)
    } else {
        item.lifecycle
            .as_deref()
            .or(item.publication_state.as_deref())
            .or(item.support_state.as_deref())
            .unwrap_or("not supplied")
            .into()
    }
}
pub(crate) fn row_label(item: &evertrace_protocol::dto::HumanSnapshotItem) -> String {
    if let Some(evertrace_protocol::dto::HumanSystemDetail::Job { detail: job }) =
        &item.system_detail
    {
        return format!(
            "{} | {:?} | {} | {}",
            job.job_kind,
            job.state,
            short(&job.target_revision),
            job.terminal_reason
                .map_or_else(|| "reason not supplied".into(), |r| format!("{r:?}"))
        );
    }
    format!(
        "{} · {} | {} | {}",
        item.object_kind,
        short(item.object_ref.as_deref().unwrap_or(&item.stable_key)),
        item.lifecycle
            .as_deref()
            .or(item.publication_state.as_deref())
            .or(item.support_state.as_deref())
            .unwrap_or("status not supplied"),
        item.scope_ref.as_deref().unwrap_or("scope not supplied")
    )
}
fn short(value: &str) -> String {
    value.chars().take(14).collect()
}
pub(crate) fn render_list(f: &mut Frame, a: Rect, state: &AppState, title: &'static str) {
    use evertrace_protocol::dto::HumanGovernanceResponse;
    if let Some(HumanGovernanceResponse::Snapshot { items, .. }) = &state.human {
        let indices = visible_indices(state);
        if !indices.is_empty() {
            use ratatui::{
                layout::Constraint,
                style::Style,
                widgets::{Block, Borders, Row, Table},
            };
            let rows = indices.into_iter().skip(state.ui.list_offset).map(|i| {
                let item = &items[i];
                let fields = row_label(item)
                    .split(" | ")
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let mut columns = vec![
                    format!(
                        "{} {}",
                        if i == state.selection { ">" } else { " " },
                        fields.first().map_or("", String::as_str)
                    ),
                    fields.get(1).cloned().unwrap_or_default(),
                ];
                if a.width >= 85 {
                    columns.push(
                        fields
                            .iter()
                            .skip(2)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" · "),
                    );
                }
                Row::new(columns).style(Style::default().fg(if i == state.selection {
                    crate::theme::EVER_OS.cyan
                } else {
                    crate::theme::EVER_OS.ink
                }))
            });
            let widths = if a.width >= 85 {
                vec![
                    Constraint::Percentage(40),
                    Constraint::Percentage(20),
                    Constraint::Percentage(40),
                ]
            } else {
                vec![Constraint::Percentage(65), Constraint::Percentage(35)]
            };
            f.render_widget(
                Table::new(rows, widths).block(
                    Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(
                            if state.ui.focus == crate::state::Focus::List {
                                crate::theme::EVER_OS.cyan
                            } else {
                                crate::theme::EVER_OS.border
                            },
                        )),
                ),
                a,
            );
            return;
        }
    }
    let body = match &state.human {
        Some(HumanGovernanceResponse::Snapshot {
            items, next_cursor, ..
        }) => {
            let indices = visible_indices(state);
            let loaded = items
                .iter()
                .filter(|item| {
                    state.route != Route::System
                        || !matches!(
                            state.ui.system_view,
                            crate::state::SystemView::Overview | crate::state::SystemView::Jobs
                        )
                        || matches!(
                            item.system_detail,
                            Some(evertrace_protocol::dto::HumanSystemDetail::Job { .. })
                        )
                })
                .count();
            let filtered = !state.ui.filter.is_empty()
                || state.ui.type_filter.is_some()
                || state.ui.scope_filter.is_some()
                || state.ui.state_filter.is_some();
            if loaded == 0 && !filtered {
                match state.route {
                    Route::Inbox => "No pending items in the visible scope",
                    Route::Explorer => {
                        "No objects in the visible scope; check capture/import in System"
                    }
                    Route::System => "No tasks on this page",
                }
                .into()
            } else if indices.is_empty() {
                format!(
                    "No matches on this page ({} loaded){}; clear filter or change page",
                    loaded,
                    if next_cursor.is_some() {
                        "; more pages available"
                    } else {
                        ""
                    }
                )
            } else {
                indices
                    .into_iter()
                    .skip(state.ui.list_offset)
                    .map(|i| {
                        format!(
                            "{} {}",
                            if i == state.selection { ">" } else { " " },
                            row_label(&items[i])
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        _ => match state.shell.connection {
            crate::ConnectionState::Disconnected => "Daemon disconnected; reconnecting",
            crate::ConnectionState::ServerStopping => "Daemon stopping; read unavailable",
            _ => "Loading this page…",
        }
        .into(),
    };
    f.render_widget(crate::components::table(title, body), a);
}

fn semantic_lines(detail: &evertrace_protocol::dto::HumanSemanticDetail) -> Vec<String> {
    use evertrace_protocol::dto::{HumanContentState, HumanSemanticContent};
    let Some(content) = &detail.content else {
        return vec![match detail.state {
            HumanContentState::TooLarge => format!(
                "Content exceeds the 32 KiB detail limit ({} bytes); body not loaded",
                detail.original_bytes
            ),
            HumanContentState::AccessDenied => {
                "Content access denied; source or repository restriction".into()
            }
            HumanContentState::Missing => {
                "Exact revision is missing; current revision was not substituted".into()
            }
            HumanContentState::Unsupported => {
                "Readable content is not supported for this object".into()
            }
            HumanContentState::Unavailable => {
                "Content read could not finish within the bounded access check".into()
            }
            HumanContentState::Ready => "Content missing from response".into(),
        }];
    };
    match content {
        HumanSemanticContent::Atom(atom) => vec![
            safe_content(&atom.value.text),
            format!(
                "Subject: {}\nPredicate: {}",
                safe_content(&atom.value.subject),
                safe_content(&atom.value.predicate)
            ),
            format!(
                "Object: {}",
                atom.value
                    .object
                    .as_deref()
                    .map(safe_content)
                    .unwrap_or_else(|| "not supplied".into())
            ),
            format!(
                "Created at: {}",
                detail::timestamp(Some(atom.created_at_us))
            ),
            format!(
                "Parent revision: {}",
                atom.parent_revision_id
                    .map_or_else(|| "none".into(), |id| id.to_string())
            ),
        ],
        HumanSemanticContent::Procedure(procedure) => {
            let draft = &procedure.draft;
            let mut lines = vec![
                safe_content(&draft.title),
                safe_content(&draft.summary),
                format!("When / stage: {}", safe_content(&draft.when.stage)),
            ];
            for (label, values) in [
                ("Goals", &draft.when.goals),
                ("Targets", &draft.when.targets),
                ("Signals", &draft.when.signals),
                ("Requires", &draft.when.requires),
                ("Excludes", &draft.when.excludes),
                ("Do", &draft.actions.stages),
                ("Avoid", &draft.actions.avoid),
                ("Done / success", &draft.done.success),
                ("Done / abort", &draft.done.abort),
                ("Done / verify", &draft.done.verify),
                ("Pitfalls", &draft.pitfalls),
            ] {
                lines.push(format!("{label}:"));
                lines.extend(
                    values
                        .iter()
                        .map(|value| format!("  {}", safe_content(value))),
                );
            }
            lines.push(format!(
                "Created at: {}",
                detail::timestamp(Some(procedure.created_at_us))
            ));
            lines.push(format!(
                "Parent revision: {}",
                procedure
                    .parent_revision_id
                    .map_or_else(|| "none".into(), |id| id.to_string())
            ));
            lines
        }
        HumanSemanticContent::CoreMembership(membership) => vec![
            format!(
                "Core membership references Atom revision {}",
                membership.atom_revision_id
            ),
            format!("Active: {}", membership.active),
        ],
    }
}

fn safe_content(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .collect()
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
    lines.extend(content_lines(item, state.competing_candidate_selection));
    if state.detail.is_some() {
        lines.push("Esc returns to list".into());
    } else {
        lines.push("Enter opens detail".into());
    }
    lines.join("\n")
}

pub(crate) fn content_lines(
    item: &evertrace_protocol::dto::HumanSnapshotItem,
    competing_candidate_selection: usize,
) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(detail) = &item.semantic_detail {
        lines.extend(semantic_lines(detail));
    }
    if let Some(base) = &item.proposal_base {
        lines.push("Exact proposal base".into());
        lines.extend(semantic_lines(base));
    }
    if let Some(detail) = &item.work_detail {
        lines.push(format!(
            "Work identity: {:?}; instruction authority: none",
            detail.identity_confidence
        ));
        lines.push("Agent-organized plan, not execution or user authorization".into());
        lines.push(format!("Goal: {}", detail.canonical_goal.escape_debug()));
        if let Some(goal) = &detail.workstream_goal {
            lines.push(format!("Workstream goal: {}", goal.escape_debug()));
        }
        if let Some(phase) = &detail.phase {
            lines.push(format!(
                "Phase: {:?} / {}",
                phase.phase_kind,
                phase.phase_label.escape_debug()
            ));
            lines.push(format!("Local goal: {}", phase.local_goal.escape_debug()));
            lines.push(format!(
                "Expected transition: {}",
                phase.expected_state_transition.escape_debug()
            ));
        }
        if let Some(acceptance) = &detail.acceptance {
            lines.push(format!("Acceptance plan: {}", acceptance.escape_debug()));
        }
        lines.push(format!(
            "Sources: {}",
            detail.source_refs.join(", ").escape_debug()
        ));
    }
    if let Some(detail) = &item.evidence_detail {
        use evertrace_domain::evidence::ProtectedPresentation;
        lines.extend([
            format!(
                "source/role: {:?} / {:?}",
                detail.source_kind, detail.source_role
            ),
            format!(
                "observation/trust: {:?} / {:?}",
                detail.observation_role, detail.content_trust
            ),
            format!(
                "capture: {:?}; instruction authority: none",
                detail.capture_completeness
            ),
            format!("protected bytes: {}", detail.protected_length),
            format!("CAS: {}", detail.cas_ref),
        ]);
        if detail.observation_role == evertrace_domain::evidence::ObservationRole::Message {
            lines.push("Observed message; acceptance or task intent not established".into());
        }
        lines.push(match &detail.protected_presentation {
            Some(ProtectedPresentation::Inline { text }) => {
                format!("protected inline: {}", text.escape_debug())
            }
            Some(ProtectedPresentation::Preview { text }) => {
                format!("protected preview (partial): {}", text.escape_debug())
            }
            Some(ProtectedPresentation::Unavailable { reason }) => {
                format!("protected presentation unavailable: {reason:?}")
            }
            None => "protected presentation unavailable".into(),
        });
    }
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
        if let Some(coverage) = &review.capability_coverage {
            lines.extend([
                format!("capability inventory: {:?}", coverage.inventory_refs),
                format!(
                    "present assets: {}; unobserved sources: {}; unknown contracts: {}",
                    coverage.present_assets,
                    coverage.unobserved_sources,
                    coverage.unknown_contracts
                ),
                format!(
                    "equivalent capability evidence: {:?}",
                    coverage.equivalent_assets
                ),
                format!(
                    "incremental boundary base: {:?}",
                    coverage.incremental_base_revision
                ),
                format!(
                    "coverage omissions: {:?}; likely redundant: {}",
                    coverage.omissions, coverage.likely_redundant
                ),
                "Unknown coverage blocks automatic acceptance, not manual review.".into(),
            ]);
        }
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
            .get(competing_candidate_selection)
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
    if let Some(preview) = &item.repository_purge_preview {
        lines.extend([
            format!(
                "repository purge: {}@{} / generation {}",
                preview.repository_id, preview.repository_revision, preview.deletion_generation
            ),
            format!(
                "CAS plan: {} exclusive item(s), {} shared item(s) retained",
                preview.planned_exclusive_cas_count, preview.shared_cas_retained_count
            ),
            format!(
                "typed global dependencies: {}; blockers: {:?}",
                preview.repository_derived_global_dependency_count, preview.blockers
            ),
            format!(
                "affected: {} session, {} Evidence/receipt/capture, {} work, {} Atom, {} Procedure",
                preview.affected_session_count,
                preview.affected_evidence_receipt_capture_count,
                preview.affected_work_count,
                preview.affected_atom_count,
                preview.affected_procedure_count
            ),
            format!(
                "research/recovery: {} run, {} result, {} artifact, {} Recovery, {} Recall/derived",
                preview.affected_experiment_run_count,
                preview.affected_result_evidence_count,
                preview.affected_artifact_count,
                preview.affected_recovery_count,
                preview.affected_recall_derived_count
            ),
            format!(
                "relationship-only impacts: {}; estimated reclaimable bytes: {}",
                preview.relationship_only_count,
                preview
                    .estimated_reclaimable_bytes
                    .map_or_else(|| "unavailable".into(), |value| value.to_string())
            ),
            format!(
                "dependency fence: {} support revalidation, {} procedure review-hold",
                preview.downstream_support_revalidation_count,
                preview.dependent_procedure_review_hold_count
            ),
            "Shared Evidence/CAS is retained; this is not source erasure.".into(),
            "P opens stable-ID re-entry; strict source erasure is unavailable; Esc cancels".into(),
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
            HumanSystemDetail::Job { detail } => {
                lines.extend([
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
                ]);
                if let Some(evertrace_protocol::dto::HumanNativeHistoryCleanupAvailability::ExternalReaderExclusionUnverified) = &detail.native_history_cleanup_availability {
                    lines.extend([
                        "Native history cleanup: unavailable now".into(),
                        "Product purge does not run this.".into(),
                        "External reader exclusion is unverified.".into(),
                    ]);
                }
                if let Some(gc) = &detail.gc_summary {
                    lines.extend([
                        format!(
                            "GC bounded batch examined/marked: {}/{}",
                            gc.examined_files, gc.marked_candidates
                        ),
                        format!(
                            "GC deleted objects/bytes: {}/{}",
                            gc.deleted_count, gc.deleted_bytes
                        ),
                        format!("GC unknown/interrupted: {}", gc.unknown_count),
                        format!(
                            "GC mark/sweep watermark: {}/{}",
                            gc.mark_watermark, gc.sweep_watermark
                        ),
                        format!("GC checksum: {}", gc.checksum),
                    ]);
                    for result in &gc.conservative_prune {
                        lines.push(match (result.old_versions, result.bytes_removed) {
                            (Some(versions), Some(bytes)) => format!(
                                "Prune {} confirmed: versions {versions}, bytes {bytes}",
                                result.table
                            ),
                            _ => format!("Prune {}: unknown/interrupted", result.table),
                        });
                    }
                    if gc.conservative_prune.is_empty() {
                        lines.push("Prune: not started/confirmed".into());
                    }
                }
                if let Some(backup) = &detail.backup_summary {
                    lines.extend([
                        format!(
                            "backup verification/frontier: {:?} / {}",
                            backup.validation_result, backup.frontier
                        ),
                        format!(
                            "backup journal/objects: v{}@{} / v{}@{}",
                            backup.journal.version,
                            backup.journal.frontier,
                            backup.objects.version,
                            backup.objects.frontier
                        ),
                        format!(
                            "backup relations/search: {} / {}",
                            backup.relations.as_ref().map_or_else(|| "absent".into(), |table| format!("v{}@{}", table.version, table.frontier)),
                            backup.search.as_ref().map_or_else(|| "absent".into(), |table| format!("v{}@{}", table.version, table.frontier))
                        ),
                        format!(
                            "backup source/spool/cas: {}/{} watermarks; {} files/{} generations; {}/{} CAS",
                            backup.committed_source_watermark_count,
                            backup.spool_source_watermark_count,
                            backup.spool_file_count,
                            backup.spool_generation_count,
                            backup.live_cas_count,
                            backup.spool_cas_count
                        ),
                        format!(
                            "backup spool normal/isolated/gap/quarantine: {}/{}/{}/{}",
                            backup.normal_spool_frame_count,
                            backup.isolated_spool_frame_count,
                            backup.emergency_gap_count,
                            backup.quarantine_count
                        ),
                        format!(
                            "backup runtime/outbox/index generation/compiler watermark: {} / {} / {} / {}",
                            backup.runtime_generation,
                            backup.runtime_outbox_watermark,
                            backup.index_generation,
                            backup.compiler_watermark
                        ),
                        format!(
                            "backup hook current/retained: {}/{}",
                            backup
                                .hook_current_generation
                                .map_or_else(|| "absent".to_owned(), |generation| generation.to_string()),
                            backup.hook_retained_generations.len()
                        ),
                        format!(
                            "backup hook pins/pinned artifacts: {}/{}",
                            backup.hook_pin_count,
                            backup.session_pinned_hook_artifact_count
                        ),
                        format!(
                            "backup config hash: {}",
                            evertrace_domain::evidence::hex(&backup.effective_config_hash)
                        ),
                        format!(
                            "backup deletion generations object/repository: {}/{}",
                            backup.object_deletion_generation,
                            backup.repository_purge_generation
                        ),
                        format!(
                            "backup files/bytes: {}/{}",
                            backup.file_count, backup.total_bytes
                        ),
                        format!(
                            "backup space required/available: {}/{}",
                            backup.required_space_bytes,
                            backup.available_space_bytes_at_preflight
                        ),
                    ]);
                }
            }
            HumanSystemDetail::Repository {
                repository_id,
                repository_revision,
                user_disabled,
                trust_revoked,
                revalidated_inventory_ref,
                worktree_id,
            } => {
                lines.extend([
                    format!("repository: {repository_id} revision {repository_revision}"),
                    format!("disabled: {user_disabled}; sticky trust revoked: {trust_revoked}"),
                    format!("restoration boundary: {revalidated_inventory_ref:?}"),
                    format!("worktree: {worktree_id:?}"),
                    "D disable; E verify and enable; R rescan (exact selected context)".into(),
                ]);
            }
            HumanSystemDetail::CapabilityInventory {
                job_id,
                repository_id,
                repository_revision,
                worktree_id,
                cwd,
                state,
                source_count,
                signature_count,
                unobserved_source_count,
                unknown_contract_count,
                asset_names,
            } => {
                lines.extend([format!("inventory: {job_id}"),
                    format!("repository: {repository_id} revision {repository_revision}; worktree: {worktree_id}"),
                    format!("cwd: {cwd}"), format!("state: {state}; sources: {source_count:?}; signatures: {signature_count:?}"),
                    format!("unobserved sources: {unobserved_source_count:?}; unknown contracts: {unknown_contract_count:?}"),
                    "Presence is not routing, adoption, or automatic Procedure coverage.".into()]);
                lines.extend(asset_names.iter().map(|name| format!("asset: {name}")));
            }
            HumanSystemDetail::SessionImport {
                session_id,
                source_instance_id,
                body_state,
                access,
                workspace,
                repository_read_restrictions,
            } => {
                lines.extend([
                    format!("session: {session_id}"),
                    format!("source: {source_instance_id}"),
                    format!("body: {body_state}"),
                    format!("access: {access}; workspace: {workspace}"),
                    format!("repository read restrictions: {repository_read_restrictions:?}"),
                ]);
            }
            HumanSystemDetail::Config {
                config_version,
                effective_config_hash,
                reload,
            } => {
                lines.extend([
                    format!("config version: {config_version}"),
                    format!(
                        "effective config hash: {}",
                        evertrace_domain::evidence::hex(effective_config_hash)
                    ),
                ]);
                if let Some(detail) = reload {
                    lines.push(format!(
                        "reload: {:?} ({:?})",
                        detail.outcome, detail.source
                    ));
                    lines.push(format!("actor: {}", detail.actor));
                }
            }
        }
    }
    lines
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
