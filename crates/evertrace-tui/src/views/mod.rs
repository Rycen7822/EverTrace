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
                && (row_label(item, state.language)
                    .to_lowercase()
                    .contains(&query)
                    || row_label(item, crate::Language::English)
                        .to_lowercase()
                        .contains(&query)
                    || item.object_kind.to_lowercase().contains(&query))
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
pub(crate) fn row_label(
    item: &evertrace_protocol::dto::HumanSnapshotItem,
    language: crate::Language,
) -> String {
    if let Some(evertrace_protocol::dto::HumanSystemDetail::Job { detail: job }) =
        &item.system_detail
    {
        return format!(
            "{} | {} | {} | {}",
            kind_label(&job.job_kind, language),
            job_state(job.state, language),
            short(&job.target_revision),
            job_reason(job.terminal_reason, language)
        );
    }
    let title = item
        .work_detail
        .as_ref()
        .map(|detail| safe_content(&detail.canonical_goal))
        .filter(|goal| !goal.trim().is_empty())
        .map(|goal| goal.chars().take(60).collect::<String>())
        .unwrap_or_else(|| short(item.object_ref.as_deref().unwrap_or(&item.stable_key)));
    let kind = kind_label(&item.object_kind, language);
    let kind = if kind == item.object_kind {
        format!("{} ({kind})", language.label(category_label(item.category)))
    } else {
        kind.to_owned()
    };
    format!(
        "{} · {} | {} | {}",
        kind,
        title,
        status_label(
            item.lifecycle
                .as_deref()
                .or(item.publication_state.as_deref())
                .or(item.support_state.as_deref())
                .unwrap_or(language.text("status not supplied", "未提供状态")),
            language
        ),
        item.scope_ref
            .as_deref()
            .unwrap_or(language.text("scope not supplied", "未提供范围"))
    )
}
pub(crate) fn status_label(value: &str, language: crate::Language) -> &str {
    if language == crate::Language::English {
        return value;
    }
    match value {
        "immutable" => "不可变记录",
        "Queued" => "排队中",
        "Leased" => "已领取",
        "Succeeded" => "已结束",
        "Failed" => "失败",
        "not supplied" => "未提供",
        "active" | "Active" => "有效",
        "current" | "Current" => "当前",
        "pending" | "Pending" => "待处理",
        "accepted" | "Accepted" => "已接受",
        "rejected" | "Rejected" => "已拒绝",
        "deferred" | "Deferred" => "已延后",
        "review_hold" | "ReviewHold" => "等待复核",
        "insufficient" | "Insufficient" => "支持不足",
        "revoked" | "Revoked" => "已撤权",
        "forgotten" | "Forgotten" => "已遗忘",
        "disabled" | "Disabled" => "已停用",
        "deprecated" | "Deprecated" => "已弃用",
        _ => value,
    }
}
pub(crate) fn job_state(
    state: evertrace_protocol::dto::HumanJobState,
    language: crate::Language,
) -> &'static str {
    use evertrace_protocol::dto::HumanJobState::*;
    match state {
        Queued => language.text("Queued", "排队中"),
        Leased => language.text("Leased", "已领取"),
        Succeeded => language.text("Ended", "已结束"),
        Failed => language.text("Failed", "失败"),
    }
}
pub(crate) fn job_reason(
    reason: Option<evertrace_protocol::dto::HumanJobTerminalReason>,
    language: crate::Language,
) -> &'static str {
    use evertrace_protocol::dto::HumanJobTerminalReason::*;
    match reason {
        None => language.text("reason not supplied", "未提供原因"),
        Some(Completed) => language.text("Completed", "已完成"),
        Some(StaleGeneration) => language.text("Stale generation", "目标代次已过时"),
        Some(BudgetExhausted) => language.text("Budget exhausted", "预算不足"),
        Some(SourceUnavailable) => language.text("Source unavailable", "来源不可用"),
        Some(Unsupported) => language.text("Unsupported", "不支持"),
        Some(SourceReplaced) => language.text("Source replaced", "来源已替换"),
        Some(Revoked) => language.text("Source revoked", "来源已撤权"),
        Some(IntegrityFailure) => language.text("Integrity failure", "完整性校验失败"),
    }
}
pub(crate) fn kind_label(kind: &str, language: crate::Language) -> &str {
    let (en, zh) = match kind {
        "atom_revision" => ("Memory statement", "记忆条目"),
        "procedure_revision" => ("Reusable procedure", "可复用步骤"),
        "core_membership" => ("Core memory membership", "核心记忆成员"),
        "revision_proposal" => ("Memory change proposal", "记忆变更提议"),
        "task" => ("Task plan", "任务计划"),
        "workstream" => ("Workstream plan", "工作流计划"),
        "work_episode" => ("Work episode", "工作片段"),
        "work_checkpoint" => ("Work checkpoint", "工作检查点"),
        "attempt" => ("Execution attempt", "执行尝试"),
        "capture_receipt" => ("Capture receipt", "采集凭据"),
        "source_observation" => ("Source observation", "来源观测"),
        "host_occurrence" => ("Host event", "宿主事件"),
        "grounded_evidence" => ("Grounded evidence", "可追溯证据"),
        "repository" => ("Repository", "仓库"),
        "session_import" => ("Session import record", "会话导入记录"),
        "semantic_digest" => ("Semantic summary", "语义摘要"),
        "recovery_bundle" => ("Recovery bundle", "恢复包"),
        "execution_lane" => ("Execution lane", "执行通道"),
        "job" => ("Background task", "后台任务"),
        "objects_projection" => ("Rebuild object index", "重建对象索引"),
        "physical_normalization" => ("Normalize captured records", "规范化采集记录"),
        "capture_reconciliation" => ("Reconcile capture completeness", "核对采集完整性"),
        "capture_artifact_reconciliation_v1" => ("Reconcile capture failures", "核对采集故障"),
        "support_closure" => ("Recheck memory support", "复核记忆依据"),
        "session_import_v1" => ("Import session records", "导入会话记录"),
        "capability_inventory_v1" => ("Inspect repository capabilities", "检查仓库能力"),
        "semantic_synthesis_v1" => ("Produce semantic summary", "生成语义摘要"),
        "procedure_review_v1" => ("Review reusable procedure", "复核可复用步骤"),
        "procedure_cohort_promotion_v1" => ("Evaluate procedure promotion", "评估步骤晋升"),
        "procedure_usage_evaluation_v1" => ("Evaluate procedure usage", "评估步骤使用反馈"),
        "quiesced_backup_create_v1" => ("Create consistent backup", "创建一致性备份"),
        "quiesced_backup_verify_v1" => ("Verify backup", "验证备份"),
        "repository_scope_purge_v1" => ("Purge repository records", "清除仓库记录"),
        "two_pass_gc_v1" => ("Reclaim unused stored content", "回收无引用的存储内容"),
        "source_receipt" => ("Captured source", "采集来源"),
        "worktree" => ("Worktree", "工作树"),
        "operation" => ("Recorded operation", "操作记录"),
        "work_binding" => ("Work binding", "工作绑定"),
        "dirty_target" => ("Pending index update", "待更新索引"),
        _ => return kind,
    };
    language.text(en, zh)
}
fn short(value: &str) -> String {
    value.chars().take(14).collect()
}
pub(crate) fn render_list(f: &mut Frame, a: Rect, state: &AppState, title: &'static str) {
    let language = state.language;
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
                let fields = row_label(item, state.language)
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
    let body =
        match &state.human {
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
                    let empty = match state.route {
                        Route::Inbox => state
                            .language
                            .label("No pending items in the visible scope"),
                        Route::Explorer => state.language.label(
                            "No objects in the visible scope; check capture/import in System",
                        ),
                        Route::System => state.language.label("No tasks on this page"),
                    };
                    if next_cursor.is_some() {
                        format!("{empty}\n{}", language.text(
                        "More pages are available. Use Next page or : Next page to continue.",
                        "还有后续页。可点击下一页，或在命令面板选择下一页。",
                    ))
                    } else {
                        empty.into()
                    }
                } else if indices.is_empty() {
                    crate::locale::format!(
                        language,
                        "No matches on this page ({} loaded){}; clear filter or change page",
                        "当前页无匹配项（已加载 {} 项）{}；可清除筛选或翻页",
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
                                row_label(&items[i], state.language)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            _ => match state.shell.connection {
                crate::ConnectionState::Disconnected => {
                    state.language.label("Daemon disconnected; reconnecting")
                }
                crate::ConnectionState::ServerStopping => {
                    state.language.label("Daemon stopping; read unavailable")
                }
                _ => state.language.label("Loading this page…"),
            }
            .into(),
        };
    f.render_widget(crate::components::table(title, body), a);
}

fn semantic_lines(
    detail: &evertrace_protocol::dto::HumanSemanticDetail,
    language: crate::Language,
) -> Vec<String> {
    use evertrace_protocol::dto::{HumanContentState, HumanSemanticContent};
    let Some(content) = &detail.content else {
        return vec![match detail.state {
            HumanContentState::TooLarge => crate::locale::format!(
                language,
                "Content exceeds the 32 KiB detail limit ({} bytes); body not loaded",
                "内容超过详情的 32 KiB 上限（{} 字节）；正文未加载",
                detail.original_bytes
            ),
            HumanContentState::AccessDenied => language
                .label("Content access denied; source or repository restriction")
                .into(),
            HumanContentState::Missing => language
                .label("Exact revision is missing; current revision was not substituted")
                .into(),
            HumanContentState::Unsupported => language
                .label("Readable content is not supported for this object")
                .into(),
            HumanContentState::Unavailable => language
                .label("Content read could not finish within the bounded access check")
                .into(),
            HumanContentState::Ready => language.label("Content missing from response").into(),
        }];
    };
    match content {
        HumanSemanticContent::Atom(atom) => vec![
            safe_content(&atom.value.text),
            crate::locale::format!(
                language,
                "Subject: {}\nPredicate: {}",
                "主体: {}\n关系: {}",
                safe_content(&atom.value.subject),
                safe_content(&atom.value.predicate)
            ),
            crate::locale::format!(
                language,
                "Object: {}",
                "对象: {}",
                atom.value
                    .object
                    .as_deref()
                    .map(safe_content)
                    .unwrap_or_else(|| "not supplied".into())
            ),
            crate::locale::format!(
                language,
                "Created at: {}",
                "创建时间: {}",
                detail::timestamp(Some(atom.created_at_us))
            ),
            crate::locale::format!(
                language,
                "Parent revision: {}",
                "父修订: {}",
                atom.parent_revision_id
                    .map_or_else(|| "none".into(), |id| id.to_string())
            ),
        ],
        HumanSemanticContent::Procedure(procedure) => {
            let draft = &procedure.draft;
            let mut lines = vec![
                safe_content(&draft.title),
                safe_content(&draft.summary),
                crate::locale::format!(
                    language,
                    "When / stage: {}",
                    "适用时机／阶段: {}",
                    safe_content(&draft.when.stage)
                ),
            ];
            for (label, values) in [
                (language.label("Goals"), &draft.when.goals),
                (language.label("Targets"), &draft.when.targets),
                (language.label("Signals"), &draft.when.signals),
                (language.label("Requires"), &draft.when.requires),
                (language.label("Excludes"), &draft.when.excludes),
                (language.label("Do"), &draft.actions.stages),
                (language.label("Avoid"), &draft.actions.avoid),
                (language.label("Done / success"), &draft.done.success),
                (language.label("Done / abort"), &draft.done.abort),
                (language.label("Done / verify"), &draft.done.verify),
                (language.label("Pitfalls"), &draft.pitfalls),
            ] {
                lines.push(format!("{label}:"));
                lines.extend(
                    values
                        .iter()
                        .map(|value| format!("  {}", safe_content(value))),
                );
            }
            lines.push(crate::locale::format!(
                language,
                "Created at: {}",
                "创建时间: {}",
                detail::timestamp(Some(procedure.created_at_us))
            ));
            lines.push(crate::locale::format!(
                language,
                "Parent revision: {}",
                "父修订: {}",
                procedure
                    .parent_revision_id
                    .map_or_else(|| "none".into(), |id| id.to_string())
            ));
            lines
        }
        HumanSemanticContent::CoreMembership(membership) => vec![
            crate::locale::format!(
                language,
                "Core membership references Atom revision {}",
                "核心记忆成员引用条目修订 {}",
                membership.atom_revision_id
            ),
            crate::locale::format!(language, "Active: {}", "有效: {}", membership.active),
        ],
    }
}

fn safe_content(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .collect()
}

pub(crate) fn inspector_text(state: &AppState) -> String {
    let language = state.language;
    if let Some(message) = &state.detail_message {
        return crate::locale::format!(
            language,
            "Detail\n{message}\nEsc returns to list",
            "详情\n{message}\nEsc 返回列表"
        );
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
        format!(
            "{} / {}",
            language.label(category_label(item.category)),
            item.object_kind
        ),
        crate::locale::format!(
            language,
            "projection frontier: {}",
            "投影水位: {}",
            frontier.map_or_else(|| "-".into(), |value| value.to_string())
        ),
        crate::locale::format!(
            language,
            "family: {:?}  class: {:?}",
            "对象族: {:?}  类别: {:?}",
            item.family,
            item.row_class
        ),
        crate::locale::format!(
            language,
            "object: {}",
            "对象: {}",
            item.object_ref.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "revision: {}",
            "修订: {}",
            item.revision_ref.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "lifecycle: {}",
            "生命周期: {}",
            item.lifecycle.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "epistemic: {}",
            "认知状态: {}",
            item.epistemic.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "authority: {}",
            "权限: {}",
            item.authority.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "publication/support: {}/{}",
            "发布／支持: {}/{}",
            item.publication_state.as_deref().unwrap_or("-"),
            item.support_state.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "scope: {}",
            "范围: {}",
            item.scope_ref.as_deref().unwrap_or("-")
        ),
        crate::locale::format!(
            language,
            "source event: {}",
            "来源事件: {}",
            item.source_event_seq
        ),
        crate::locale::format!(language, "audit row: {}", "审计记录: {}", item.stable_key),
        daemon_status,
    ];
    lines.extend(content_lines(
        item,
        state.competing_candidate_selection,
        language,
    ));
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
    language: crate::Language,
) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(detail) = &item.semantic_detail {
        lines.extend(semantic_lines(detail, language));
    }
    if let Some(base) = &item.proposal_base {
        lines.push(language.label("Exact proposal base").into());
        lines.extend(semantic_lines(base, language));
    }
    if let Some(detail) = &item.work_detail {
        lines.push(crate::locale::format!(
            language,
            "Work identity: {:?}; instruction authority: none",
            "工作身份: {:?}; 不具备指令权限",
            detail.identity_confidence
        ));
        lines.push(
            language
                .label("Agent-organized plan, not execution or user authorization")
                .into(),
        );
        lines.push(crate::locale::format!(
            language,
            "Goal: {}",
            "目标: {}",
            detail.canonical_goal.escape_debug()
        ));
        if let Some(goal) = &detail.workstream_goal {
            lines.push(crate::locale::format!(
                language,
                "Workstream goal: {}",
                "工作流目标: {}",
                goal.escape_debug()
            ));
        }
        if let Some(phase) = &detail.phase {
            lines.push(crate::locale::format!(
                language,
                "Phase: {:?} / {}",
                "阶段: {:?} / {}",
                phase.phase_kind,
                phase.phase_label.escape_debug()
            ));
            lines.push(crate::locale::format!(
                language,
                "Local goal: {}",
                "阶段目标: {}",
                phase.local_goal.escape_debug()
            ));
            lines.push(crate::locale::format!(
                language,
                "Expected transition: {}",
                "预期转变: {}",
                phase.expected_state_transition.escape_debug()
            ));
        }
        if let Some(acceptance) = &detail.acceptance {
            lines.push(crate::locale::format!(
                language,
                "Acceptance plan: {}",
                "验收计划: {}",
                acceptance.escape_debug()
            ));
        }
        lines.push(crate::locale::format!(
            language,
            "Sources: {}",
            "来源: {}",
            detail.source_refs.join(", ").escape_debug()
        ));
    }
    if let Some(detail) = &item.evidence_detail {
        use evertrace_domain::evidence::ProtectedPresentation;
        lines.extend([
            crate::locale::format!(
                language,
                "source/role: {:?} / {:?}",
                "来源／角色: {:?} / {:?}",
                detail.source_kind,
                detail.source_role
            ),
            crate::locale::format!(
                language,
                "observation/trust: {:?} / {:?}",
                "观测／可信度: {:?} / {:?}",
                detail.observation_role,
                detail.content_trust
            ),
            crate::locale::format!(
                language,
                "capture: {:?}; instruction authority: none",
                "采集: {:?}; 不具备指令权限",
                detail.capture_completeness
            ),
            crate::locale::format!(
                language,
                "protected bytes: {}",
                "受保护字节数: {}",
                detail.protected_length
            ),
            format!("CAS: {}", detail.cas_ref),
        ]);
        if detail.observation_role == evertrace_domain::evidence::ObservationRole::Message {
            lines.push(
                language
                    .label("Observed message; acceptance or task intent not established")
                    .into(),
            );
        }
        lines.push(match &detail.protected_presentation {
            Some(ProtectedPresentation::Inline { text }) => {
                crate::locale::format!(
                    language,
                    "protected inline: {}",
                    "受保护内联内容: {}",
                    text.escape_debug()
                )
            }
            Some(ProtectedPresentation::Preview { text }) => {
                format!("protected preview (partial): {}", text.escape_debug())
            }
            Some(ProtectedPresentation::Unavailable { reason }) => {
                crate::locale::format!(
                    language,
                    "protected presentation unavailable: {reason:?}",
                    "受保护内容不可显示: {reason:?}"
                )
            }
            None => language.label("protected presentation unavailable").into(),
        });
    }
    if let Some(proposal) = &item.proposal {
        lines.extend([
            crate::locale::format!(
                language,
                "target: {:?} {:?}",
                "目标: {:?} {:?}",
                proposal.target_kind,
                proposal.target_id
            ),
            crate::locale::format!(
                language,
                "operation/base: {:?} {}",
                "操作／原版本: {:?} {}",
                proposal.operation,
                proposal
                    .base_revision_id
                    .map_or_else(|| "-".into(), |value| value.to_string())
            ),
            crate::locale::format!(
                language,
                "eligibility/status: {:?}/{:?}",
                "资格／状态: {:?}/{:?}",
                proposal.eligibility,
                proposal.status
            ),
            crate::locale::format!(
                language,
                "fingerprint: {}",
                "指纹: {}",
                proposal.fingerprint
            ),
            crate::locale::format!(
                language,
                "source cohort ({}): {}",
                "来源集合 ({}): {}",
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
            crate::locale::format!(
                language,
                "plain accept eligible: {}",
                "可直接接受: {}",
                review.plain_accept_eligible
            ),
            crate::locale::format!(
                language,
                "merge-and-accept eligible: {}",
                "可合并接受: {}",
                review.merge_and_accept_eligible
            ),
            crate::locale::format!(
                language,
                "created by: {:?}",
                "创建者: {:?}",
                review.proposal.created_by
            ),
            crate::locale::format!(
                language,
                "proposal evidence: {:?}",
                "提议证据: {:?}",
                review.proposal.evidence_refs
            ),
            crate::locale::format!(
                language,
                "review payload:\n{:#?}",
                "审阅内容:\n{:#?}",
                review.proposal.payload
            ),
        ]);
        lines.push(language.label("edit-and-accept: unavailable").into());
        if let Some(coverage) = &review.capability_coverage {
            lines.extend([
                crate::locale::format!(
                    language,
                    "capability inventory: {:?}",
                    "能力清单: {:?}",
                    coverage.inventory_refs
                ),
                crate::locale::format!(
                    language,
                    "present assets: {}; unobserved sources: {}; unknown contracts: {}",
                    "已存在资料: {}; 未观测来源: {}; 未知合同: {}",
                    coverage.present_assets,
                    coverage.unobserved_sources,
                    coverage.unknown_contracts
                ),
                crate::locale::format!(
                    language,
                    "equivalent capability evidence: {:?}",
                    "等效能力证据: {:?}",
                    coverage.equivalent_assets
                ),
                crate::locale::format!(
                    language,
                    "incremental boundary base: {:?}",
                    "增量边界原版本: {:?}",
                    coverage.incremental_base_revision
                ),
                crate::locale::format!(
                    language,
                    "coverage omissions: {:?}; likely redundant: {}",
                    "覆盖缺失: {:?}; 可能重复: {}",
                    coverage.omissions,
                    coverage.likely_redundant
                ),
                language
                    .label("Unknown coverage blocks automatic acceptance, not manual review.")
                    .into(),
            ]);
        }
        if let Some(reference) = &review.reauthorization {
            lines.extend([
                language
                    .label("re-authorize forgotten object: available")
                    .into(),
                crate::locale::format!(
                    language,
                    "forgotten target: {:?}",
                    "已遗忘目标: {:?}",
                    reference.target
                ),
                crate::locale::format!(
                    language,
                    "deletion generation: {}",
                    "删除代次: {}",
                    reference.deletion_generation
                ),
                crate::locale::format!(
                    language,
                    "purge audit ref: {}",
                    "清除审计引用: {}",
                    reference.purge_job_audit_ref
                ),
                language.label("R re-authorize forgotten object").into(),
            ]);
        }
    }
    if let Some(support) = &item.support_detail {
        lines.extend([
            crate::locale::format!(
                language,
                "support contract/validation: {} / {}",
                "支持合同／验证: {} / {}",
                support.support_contract_revision_id,
                support.validation_revision_id
            ),
            crate::locale::format!(
                language,
                "support successor: {}",
                "支持后继: {}",
                support.successor_ref
            ),
            crate::locale::format!(
                language,
                "support state/generation: {:?} / {}",
                "支持状态／代次: {:?} / {}",
                support.state,
                support.dependency_generation
            ),
            crate::locale::format!(
                language,
                "threshold: minimum={} authorization={} degraded={}",
                "阈值: 最少={} 授权={} 降级={}",
                support.threshold.minimum_surviving_support,
                support.threshold.require_authorization,
                support.provenance_degraded
            ),
            crate::locale::format!(
                language,
                "support refs: {:?}",
                "支持引用: {:?}",
                support.support_revision_refs
            ),
            crate::locale::format!(
                language,
                "authorization refs: {:?}",
                "授权引用: {:?}",
                support.authorization_revision_refs
            ),
            crate::locale::format!(
                language,
                "surviving refs: {:?}",
                "保留引用: {:?}",
                support.surviving_support_refs
            ),
            crate::locale::format!(
                language,
                "invalid/missing refs: {:?}",
                "无效／缺失引用: {:?}",
                support.invalid_or_missing_refs
            ),
            crate::locale::format!(
                language,
                "trigger refs: {:?}",
                "触发引用: {:?}",
                support.trigger_refs
            ),
        ]);
    }
    if let Some(detail) = &item.competing_detail {
        let selected = detail
            .eligible_attempt_ids
            .get(competing_candidate_selection)
            .map_or_else(|| "-".into(), ToString::to_string);
        lines.extend([
            crate::locale::format!(
                language,
                "competing revision: {}",
                "竞争修订: {}",
                detail.expected_group_revision_id
            ),
            crate::locale::format!(
                language,
                "eligible attempts: {:?}",
                "可选尝试: {:?}",
                detail.eligible_attempt_ids
            ),
            crate::locale::format!(
                language,
                "selected winner: {selected}",
                "选中胜出项: {selected}"
            ),
            language
                .label("[/] choose; c stages selected winner; Enter confirms; Esc cancels")
                .into(),
        ]);
    }
    if let Some(preview) = &item.forget_preview {
        lines.extend([
            crate::locale::format!(
                language,
                "forget target: {:?}",
                "遗忘目标: {:?}",
                preview.target
            ),
            crate::locale::format!(
                language,
                "current revision: {}",
                "当前修订: {}",
                preview.current_revision_id
            ),
            crate::locale::format!(
                language,
                "closure: {} revision(s), deletion generation {}",
                "影响闭包：{} 个修订，删除代次 {}",
                preview.exact_revision_ids.len(),
                preview.deletion_generation
            ),
            crate::locale::format!(
                language,
                "sources: {} shared retained, {} source(s) / {} span key(s) suppressed",
                "来源：保留共享项 {}，抑制来源 {}／片段键 {}",
                preview.shared_source_count,
                preview.suppressed_source_count,
                preview.suppression_ref_count
            ),
            crate::locale::format!(
                language,
                "dependency fence: {} support revalidation, {} procedure review-hold",
                "依赖隔离: {} 支持重新验证, {} 步骤待复核",
                preview.downstream_support_revalidation_count,
                preview.dependent_procedure_review_hold_count
            ),
            language
                .label("Shared source/Evidence is retained by default; this is not source erasure.")
                .into(),
            language
                .label("F stages human-only Forget; Enter confirms once; Esc cancels")
                .into(),
        ]);
    }
    if let Some(preview) = &item.repository_purge_preview {
        lines.extend([
            crate::locale::format!(
                language,
                "repository purge: {}@{} / generation {}",
                "仓库清除: {}@{} / 代次 {}",
                preview.repository_id,
                preview.repository_revision,
                preview.deletion_generation
            ),
            crate::locale::format!(
                language,
                "CAS plan: {} exclusive item(s), {} shared item(s) retained",
                "CAS 计划：独占项 {}，保留共享项 {}",
                preview.planned_exclusive_cas_count,
                preview.shared_cas_retained_count
            ),
            crate::locale::format!(
                language,
                "typed global dependencies: {}; blockers: {:?}",
                "有类型全局依赖: {}; 阻塞原因: {:?}",
                preview.repository_derived_global_dependency_count,
                preview.blockers
            ),
            crate::locale::format!(
                language,
                "affected: {} session, {} Evidence/receipt/capture, {} work, {} Atom, {} Procedure",
                "影响：会话 {}，证据／凭据／采集 {}，工作 {}，条目 {}，步骤 {}",
                preview.affected_session_count,
                preview.affected_evidence_receipt_capture_count,
                preview.affected_work_count,
                preview.affected_atom_count,
                preview.affected_procedure_count
            ),
            crate::locale::format!(
                language,
                "research/recovery: {} run, {} result, {} artifact, {} Recovery, {} Recall/derived",
                "研究／恢复：运行 {}，结果 {}，产物 {}，恢复 {}，召回／派生 {}",
                preview.affected_experiment_run_count,
                preview.affected_result_evidence_count,
                preview.affected_artifact_count,
                preview.affected_recovery_count,
                preview.affected_recall_derived_count
            ),
            crate::locale::format!(
                language,
                "relationship-only impacts: {}; estimated reclaimable bytes: {}",
                "仅关系影响: {}; 预计可回收字节: {}",
                preview.relationship_only_count,
                preview
                    .estimated_reclaimable_bytes
                    .map_or_else(|| "unavailable".into(), |value| value.to_string())
            ),
            crate::locale::format!(
                language,
                "dependency fence: {} support revalidation, {} procedure review-hold",
                "依赖隔离: {} 支持重新验证, {} 步骤待复核",
                preview.downstream_support_revalidation_count,
                preview.dependent_procedure_review_hold_count
            ),
            language
                .label("Shared Evidence/CAS is retained; this is not source erasure.")
                .into(),
            language
                .label(
                    "P opens stable-ID re-entry; strict source erasure is unavailable; Esc cancels",
                )
                .into(),
        ]);
    }
    if let Some(review) = &item.negative_review {
        lines.extend([
            crate::locale::format!(
                language,
                "negative evidence: {}",
                "负面证据: {}",
                review.negative_evidence_id
            ),
            crate::locale::format!(
                language,
                "review revision/status: {} / {:?}",
                "复核修订／状态: {} / {:?}",
                review.current_review_revision_id,
                review.status
            ),
            crate::locale::format!(
                language,
                "available decisions: {:?}",
                "可用决定: {:?}",
                review.available_decisions
            ),
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
                crate::locale::format!(language, "request/revision: {request_id} / {revision_id}", "请求／修订: {request_id} / {revision_id}"),
                crate::locale::format!(language, "repository/worktree: {repository_id} / {worktree_id}", "仓库／工作树: {repository_id} / {worktree_id}"),
                crate::locale::format!(language, "destructive/untracked: {destructive_class:?} / {untracked_scope:?}", "破坏性／未跟踪: {destructive_class:?} / {untracked_scope:?}"),
                crate::locale::format!(language, "request status: {status:?}", "请求状态: {status:?}"),
                crate::locale::format!(language, "bundle: {}", "恢复包: {}",
                    bundle_id.map_or_else(|| "-".into(), |value| value.to_string())
                ),
                crate::locale::format!(language, "reason codes: {reason_codes:?}", "原因码: {reason_codes:?}"),
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
                crate::locale::format!(language, "bundle: {bundle_id}", "恢复包: {bundle_id}"),
                crate::locale::format!(language, "source worktree/snapshot: {source_worktree_id} / {source_snapshot_id}", "来源工作树／快照: {source_worktree_id} / {source_snapshot_id}"),
                crate::locale::format!(language, "capture/order: {capture_status:?} / {ordering_integrity:?}", "采集／顺序: {capture_status:?} / {ordering_integrity:?}"),
                crate::locale::format!(language, "captured bytes: {captured_bytes}", "采集字节数: {captured_bytes}"),
                crate::locale::format!(language, "content counts: diff {tracked_diff_count}, files {tracked_file_count}, index {index_state_count}, untracked {untracked_file_count}, artifacts {untracked_artifact_count}, metadata {metadata_artifact_count}, config/run {config_run_count}", "内容计数：差异 {tracked_diff_count}，文件 {tracked_file_count}，索引 {index_state_count}，未跟踪 {untracked_file_count}，产物 {untracked_artifact_count}，元数据 {metadata_artifact_count}，配置／运行 {config_run_count}"
                ),
                crate::locale::format!(language, "attempt anchors: {attempt_anchor_count}", "尝试锚点: {attempt_anchor_count}"),
                crate::locale::format!(language, "omissions: {omission_counts:?}", "缺失: {omission_counts:?}"),
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
                crate::locale::format!(language, "application/revision: {application_id} / {revision_id}", "应用／修订: {application_id} / {revision_id}"),
                crate::locale::format!(language, "bundle/target: {bundle_id} / {target_worktree_id}", "恢复包／目标: {bundle_id} / {target_worktree_id}"),
                crate::locale::format!(language, "kind/delivery/status: {application_kind:?} / {input_delivery_state:?} / {status:?}", "类型／投递／状态: {application_kind:?} / {input_delivery_state:?} / {status:?}"),
                crate::locale::format!(language, "pre/post snapshot: {pre_snapshot_id} / {}", "之前／之后快照: {pre_snapshot_id} / {}",
                    post_snapshot_id.map_or_else(|| "-".into(), |value| value.to_string())
                ),
                crate::locale::format!(language, "selected inputs/results/verifiers: {selected_input_count}/{result_count}/{verifier_count}", "所选输入／结果／验证器: {selected_input_count}/{result_count}/{verifier_count}"),
            ]),
        }
    }
    if let Some(detail) = &item.worktree_detail {
        lines.extend([
            crate::locale::format!(
                language,
                "worktree/repository: {} / {}",
                "工作树／仓库: {} / {}",
                detail.worktree_id,
                detail.repository_id
            ),
            crate::locale::format!(
                language,
                "kind/lifecycle: {:?} / {:?}",
                "类型／生命周期: {:?} / {:?}",
                detail.kind,
                detail.lifecycle
            ),
            crate::locale::format!(
                language,
                "registration: {:?}",
                "注册: {:?}",
                detail.registration_state
            ),
            crate::locale::format!(
                language,
                "current snapshot: {}",
                "当前快照: {}",
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
                crate::locale::format!(language, "lane/revision: {execution_lane_id} / {lane_revision}", "通道／修订: {execution_lane_id} / {lane_revision}"),
                crate::locale::format!(language, "parent lane: {}", "父通道: {}",
                    parent_lane_id.map_or_else(|| "-".into(), |value| value.to_string())
                ),
                crate::locale::format!(language, "status/terminal/liveness: {status:?} / {terminal_kind:?} / {liveness_state:?}", "状态／终止／存活: {status:?} / {terminal_kind:?} / {liveness_state:?}"),
                crate::locale::format!(language, "finalized/watermark: {finalized} / {event_watermark}", "已收尾／水位: {finalized} / {event_watermark}"),
                crate::locale::format!(language, "active receipt: {active_capture_receipt_revision_id}", "当前采集凭据: {active_capture_receipt_revision_id}"),
                crate::locale::format!(language, "coverage/source: {coverage_level:?} / {source_coverage:?}", "覆盖／来源: {coverage_level:?} / {source_coverage:?}"),
                crate::locale::format!(language, "pairing/payload/order: {pairing_integrity:?} / {payload_integrity:?} / {ordering_integrity:?}", "配对／内容／顺序: {pairing_integrity:?} / {payload_integrity:?} / {ordering_integrity:?}"),
                crate::locale::format!(language, "reasoning visibility: {reasoning_visibility:?}", "推理可见性: {reasoning_visibility:?}"),
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
                crate::locale::format!(language, "receipt/lane: {capture_receipt_revision_id} / {execution_lane_id}", "凭据／通道: {capture_receipt_revision_id} / {execution_lane_id}"),
                crate::locale::format!(language, "predecessor: {}", "前序: {}", predecessor_revision_id.map_or_else(|| "-".into(), |value| value.to_string())),
                crate::locale::format!(language, "admission/identity: {admission_failure_observability:?} / {identity_strength:?}", "接纳／身份: {admission_failure_observability:?} / {identity_strength:?}"),
                crate::locale::format!(language, "delegation/child/parent/lifecycle: {delegation_start_seen}/{child_session_linked}/{parent_session_end_seen}/{lifecycle_end_seen}", "委派／子会话／父会话／生命周期：{delegation_start_seen}/{child_session_linked}/{parent_session_end_seen}/{lifecycle_end_seen}"),
                crate::locale::format!(language, "terminal/finalized: {terminal_event_kind:?} / {finalized}", "终止／已收尾: {terminal_event_kind:?} / {finalized}"),
                crate::locale::format!(language, "sequence: {first_sequence:?}..{last_sequence:?}; gaps {sequence_gap_count}; outages {outage_count}", "序列: {first_sequence:?}..{last_sequence:?}; 缺口 {sequence_gap_count}; 中断 {outage_count}"),
                crate::locale::format!(language, "tool calls/results/unmatched: {tool_call_count}/{tool_result_count}/{unmatched_tool_call_count}/{unmatched_tool_result_count}", "工具调用／结果／未配对：{tool_call_count}/{tool_result_count}/{unmatched_tool_call_count}/{unmatched_tool_result_count}"),
                crate::locale::format!(language, "truncated/redacted/corrupt/unsupported: {truncation_count}/{redaction_count}/{corrupt_count}/{unsupported_count}", "截断／脱敏／损坏／不支持：{truncation_count}/{redaction_count}/{corrupt_count}/{unsupported_count}"),
                crate::locale::format!(language, "import watermark: {import_watermark}", "导入水位: {import_watermark}"),
                crate::locale::format!(language, "coverage/source: {coverage_level:?} / {source_coverage:?}", "覆盖／来源: {coverage_level:?} / {source_coverage:?}"),
                crate::locale::format!(language, "pairing/payload/order: {pairing_integrity:?} / {payload_integrity:?} / {ordering_integrity:?}", "配对／内容／顺序: {pairing_integrity:?} / {payload_integrity:?} / {ordering_integrity:?}"),
                crate::locale::format!(language, "reasoning visibility: {reasoning_visibility:?}", "推理可见性: {reasoning_visibility:?}"),
                crate::locale::format!(language, "exact replay/resolver: {exact_byte_replay} / {resolver_version}", "精确回放／解析器: {exact_byte_replay} / {resolver_version}"),
            ]),
        }
    }
    if let Some(detail) = &item.system_detail {
        use evertrace_protocol::dto::HumanSystemDetail;
        match detail {
            HumanSystemDetail::Job { detail } => {
                lines.extend([
                    crate::locale::format!(language, "job: {}", "后台任务: {}", detail.job_id),
                    crate::locale::format!(
                        language,
                        "target: {} @ {}/{}",
                        "目标: {} @ {}/{}",
                        detail.target_revision,
                        detail.target_watermark,
                        detail.target_generation
                    ),
                    crate::locale::format!(
                        language,
                        "kind/algorithm/model: {} / {} / {:?}",
                        "类型／算法／模型: {} / {} / {:?}",
                        detail.job_kind,
                        detail.algorithm_revision,
                        detail.model_id
                    ),
                    crate::locale::format!(
                        language,
                        "priority/state/attempt: {} / {:?} / {}",
                        "优先级／状态／尝试次数: {} / {:?} / {}",
                        detail.priority,
                        detail.state,
                        detail.attempt
                    ),
                    crate::locale::format!(
                        language,
                        "backoff/lease: {:?} / {:?}",
                        "退避／租约: {:?} / {:?}",
                        detail.backoff_until_us,
                        detail.lease_until_us
                    ),
                    crate::locale::format!(
                        language,
                        "config hash: {}",
                        "配置哈希: {}",
                        evertrace_domain::evidence::hex(&detail.config_hash)
                    ),
                    crate::locale::format!(
                        language,
                        "budget: items {} bytes {:?} input {:?} output {:?} calls {:?} wall {}ms",
                        "预算：项数 {}，字节 {:?}，输入 {:?}，输出 {:?}，调用 {:?}，耗时 {}ms",
                        detail.budget.max_items,
                        detail.budget.max_bytes,
                        detail.budget.max_input_tokens,
                        detail.budget.max_output_tokens,
                        detail.budget.max_calls,
                        detail.budget.max_wall_time_ms
                    ),
                    crate::locale::format!(
                        language,
                        "terminal: {:?} / {:?}",
                        "终止结果: {:?} / {:?}",
                        detail.terminal_reason,
                        detail.terminal_result_ref
                    ),
                ]);
                if let Some(evertrace_protocol::dto::HumanNativeHistoryCleanupAvailability::ExternalReaderExclusionUnverified) = &detail.native_history_cleanup_availability {
                    lines.extend([
                        language.label("Native history cleanup: unavailable now").into(),
                        language.label("Product purge does not run this.").into(),
                        language.label("External reader exclusion is unverified.").into(),
                    ]);
                }
                if let Some(gc) = &detail.gc_summary {
                    lines.extend([
                        crate::locale::format!(
                            language,
                            "GC bounded batch examined/marked: {}/{}",
                            "回收有界批次，已检查／已标记：{}/{}",
                            gc.examined_files,
                            gc.marked_candidates
                        ),
                        crate::locale::format!(
                            language,
                            "GC deleted objects/bytes: {}/{}",
                            "回收删除对象／字节：{}/{}",
                            gc.deleted_count,
                            gc.deleted_bytes
                        ),
                        crate::locale::format!(
                            language,
                            "GC unknown/interrupted: {}",
                            "回收未知／中断：{}",
                            gc.unknown_count
                        ),
                        crate::locale::format!(
                            language,
                            "GC mark/sweep watermark: {}/{}",
                            "回收标记／清扫水位：{}/{}",
                            gc.mark_watermark,
                            gc.sweep_watermark
                        ),
                        crate::locale::format!(
                            language,
                            "GC checksum: {}",
                            "回收校验和：{}",
                            gc.checksum
                        ),
                    ]);
                    for result in &gc.conservative_prune {
                        lines.push(match (result.old_versions, result.bytes_removed) {
                            (Some(versions), Some(bytes)) => crate::locale::format!(
                                language,
                                "Prune {} confirmed: versions {versions}, bytes {bytes}",
                                "版本清理 {} 已确认：版本 {versions}，字节 {bytes}",
                                result.table
                            ),
                            _ => crate::locale::format!(
                                language,
                                "Prune {}: unknown/interrupted",
                                "版本清理 {}：未知／中断",
                                result.table
                            ),
                        });
                    }
                    if gc.conservative_prune.is_empty() {
                        lines.push(language.label("Prune: not started/confirmed").into());
                    }
                }
                if let Some(backup) = &detail.backup_summary {
                    lines.extend([
                        crate::locale::format!(language, "backup verification/frontier: {:?} / {}", "备份验证／水位: {:?} / {}",
                            backup.validation_result, backup.frontier
                        ),
                        crate::locale::format!(language, "backup journal/objects: v{}@{} / v{}@{}", "备份日志／对象：v{}@{} / v{}@{}",
                            backup.journal.version,
                            backup.journal.frontier,
                            backup.objects.version,
                            backup.objects.frontier
                        ),
                        crate::locale::format!(language, "backup relations/search: {} / {}", "备份关系／搜索：{} / {}",
                            backup.relations.as_ref().map_or_else(|| "absent".into(), |table| format!("v{}@{}", table.version, table.frontier)),
                            backup.search.as_ref().map_or_else(|| "absent".into(), |table| format!("v{}@{}", table.version, table.frontier))
                        ),
                        crate::locale::format!(language, "backup source/spool/cas: {}/{} watermarks; {} files/{} generations; {}/{} CAS", "备份来源／队列／CAS：水位 {}/{}；文件 {}／代次 {}；CAS {}/{}",
                            backup.committed_source_watermark_count,
                            backup.spool_source_watermark_count,
                            backup.spool_file_count,
                            backup.spool_generation_count,
                            backup.live_cas_count,
                            backup.spool_cas_count
                        ),
                        crate::locale::format!(language, "backup spool normal/isolated/gap/quarantine: {}/{}/{}/{}", "备份队列，正常／隔离／缺口／检疫：{}/{}/{}/{}",
                            backup.normal_spool_frame_count,
                            backup.isolated_spool_frame_count,
                            backup.emergency_gap_count,
                            backup.quarantine_count
                        ),
                        crate::locale::format!(language, "backup runtime/outbox/index generation/compiler watermark: {} / {} / {} / {}", "备份运行／发件箱／索引代次／编译水位：{} / {} / {} / {}",
                            backup.runtime_generation,
                            backup.runtime_outbox_watermark,
                            backup.index_generation,
                            backup.compiler_watermark
                        ),
                        crate::locale::format!(language, "backup hook current/retained: {}/{}", "备份钩子，当前／保留：{}/{}",
                            backup
                                .hook_current_generation
                                .map_or_else(|| "absent".to_owned(), |generation| generation.to_string()),
                            backup.hook_retained_generations.len()
                        ),
                        crate::locale::format!(language, "backup hook pins/pinned artifacts: {}/{}", "备份钩子，固定引用／固定产物：{}/{}",
                            backup.hook_pin_count,
                            backup.session_pinned_hook_artifact_count
                        ),
                        crate::locale::format!(language, "backup config hash: {}", "备份配置哈希：{}",
                            evertrace_domain::evidence::hex(&backup.effective_config_hash)
                        ),
                        crate::locale::format!(language, "backup deletion generations object/repository: {}/{}", "备份删除代次，对象／仓库：{}/{}",
                            backup.object_deletion_generation,
                            backup.repository_purge_generation
                        ),
                        crate::locale::format!(language, "backup files/bytes: {}/{}", "备份文件／字节：{}/{}",
                            backup.file_count, backup.total_bytes
                        ),
                        crate::locale::format!(language, "backup space required/available: {}/{}", "备份空间，需要／可用：{}/{}",
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
                    crate::locale::format!(
                        language,
                        "repository: {repository_id} revision {repository_revision}",
                        "仓库: {repository_id} 修订 {repository_revision}"
                    ),
                    crate::locale::format!(
                        language,
                        "disabled: {user_disabled}; sticky trust revoked: {trust_revoked}",
                        "已停用: {user_disabled}; 持久信任撤销: {trust_revoked}"
                    ),
                    crate::locale::format!(
                        language,
                        "restoration boundary: {revalidated_inventory_ref:?}",
                        "恢复边界: {revalidated_inventory_ref:?}"
                    ),
                    crate::locale::format!(
                        language,
                        "worktree: {worktree_id:?}",
                        "工作树: {worktree_id:?}"
                    ),
                    language
                        .label("D disable; E verify and enable; R rescan (exact selected context)")
                        .into(),
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
                lines.extend([crate::locale::format!(language, "inventory: {job_id}", "清单: {job_id}"),
                    crate::locale::format!(language, "repository: {repository_id} revision {repository_revision}; worktree: {worktree_id}", "仓库: {repository_id} 修订 {repository_revision}; 工作树: {worktree_id}"),
                    crate::locale::format!(language, "cwd: {cwd}", "工作目录: {cwd}"), crate::locale::format!(language, "state: {state}; sources: {source_count:?}; signatures: {signature_count:?}", "状态: {state}; 来源: {source_count:?}; 签名: {signature_count:?}"),
                    crate::locale::format!(language, "unobserved sources: {unobserved_source_count:?}; unknown contracts: {unknown_contract_count:?}", "未观测来源: {unobserved_source_count:?}; 未知合同: {unknown_contract_count:?}"),
                    language.label("Presence is not routing, adoption, or automatic Procedure coverage.").into()]);
                lines.extend(
                    asset_names.iter().map(|name| {
                        crate::locale::format!(language, "asset: {name}", "资料: {name}")
                    }),
                );
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
                    crate::locale::format!(language, "session: {session_id}", "会话: {session_id}"),
                    crate::locale::format!(
                        language,
                        "source: {source_instance_id}",
                        "来源: {source_instance_id}"
                    ),
                    crate::locale::format!(language, "body: {body_state}", "正文: {body_state}"),
                    crate::locale::format!(
                        language,
                        "access: {access}; workspace: {workspace}",
                        "访问: {access}; 工作区: {workspace}"
                    ),
                    crate::locale::format!(
                        language,
                        "repository read restrictions: {repository_read_restrictions:?}",
                        "仓库读取限制: {repository_read_restrictions:?}"
                    ),
                ]);
            }
            HumanSystemDetail::Config {
                config_version,
                effective_config_hash,
                reload,
            } => {
                lines.extend([
                    crate::locale::format!(
                        language,
                        "config version: {config_version}",
                        "配置版本: {config_version}"
                    ),
                    crate::locale::format!(
                        language,
                        "effective config hash: {}",
                        "生效配置哈希: {}",
                        evertrace_domain::evidence::hex(effective_config_hash)
                    ),
                ]);
                if let Some(detail) = reload {
                    lines.push(crate::locale::format!(
                        language,
                        "reload: {:?} ({:?})",
                        "重载: {:?} ({:?})",
                        detail.outcome,
                        detail.source
                    ));
                    lines.push(crate::locale::format!(
                        language,
                        "actor: {}",
                        "操作者: {}",
                        detail.actor
                    ));
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
