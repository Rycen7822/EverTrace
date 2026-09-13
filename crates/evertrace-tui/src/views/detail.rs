use crate::{AppState, state::DetailView};
use evertrace_protocol::dto::{HumanSemanticContent, HumanSnapshotItem, HumanSystemDetail};

pub(crate) fn wrap_content(text: &str, width: u16) -> Vec<String> {
    use ratatui::{
        style::Style,
        text::{Line, Span},
    };
    let width = usize::from(width.max(1));
    let mut result = Vec::new();
    for line in text.split('\n') {
        let span = Span::raw(line);
        let mut row = String::new();
        let mut used = 0;
        for glyph in span.styled_graphemes(Style::default()) {
            let size = Line::from(glyph.symbol).width();
            if used + size > width && !row.is_empty() {
                result.push(std::mem::take(&mut row));
                used = 0;
            }
            row.push_str(glyph.symbol);
            used += size;
        }
        result.push(row);
    }
    result
}

pub(crate) fn detail_text(state: &AppState) -> String {
    let language = state.language;
    let Some(item) = state.detail.as_ref() else {
        return state
            .language
            .label("Open an item to read its content")
            .into();
    };
    if state.ui.detail_view == DetailView::Technical {
        return super::inspector_text(state);
    }
    let mut lines = vec![
        super::row_label(item, state.language),
        crate::locale::format!(
            language,
            "Selected revision · scope: {}",
            "所选版本 · 范围：{}",
            item.scope_ref
                .as_deref()
                .unwrap_or(state.language.label("not supplied"))
        ),
    ];
    if let Some(source) = &item.source_context {
        lines.push(crate::locale::format!(
            language,
            "Source directory (recorded hint): {}\nSession: {}\nSource event: {}\nRecorded at: {}",
            "来源目录（记录中的提示）：{}\n会话：{}\n来源事件时间：{}\n记录时间：{}",
            source
                .directory
                .as_deref()
                .map(super::safe_content)
                .unwrap_or_else(|| language.text("unknown", "未知").into()),
            super::safe_content(&source.session),
            timestamp(Some(source.event_time_us)),
            timestamp(Some(source.recorded_at_us))
        ));
    } else if matches!(
        item.object_kind.as_str(),
        "source_receipt" | "source_observation" | "host_occurrence"
    ) {
        lines.push(
            language
                .text(
                    "Source directory / session / time: unavailable",
                    "来源目录／会话／时间：不可用",
                )
                .into(),
        );
    }
    if item.proposal_review.is_some() {
        lines.extend(proposal_diff(item, language));
        return lines.join("\n");
    }
    if let Some(semantic) = &item.semantic_detail {
        lines.extend(super::semantic_lines(semantic, language));
    } else if let Some(HumanSystemDetail::Job { detail: job }) = &item.system_detail {
        lines.extend([
            crate::locale::format!(
                language,
                "Task: {}\nState: {} (leased means claimed, not a model call)",
                "任务：{}\n状态：{}（已领取不等于正在调用模型）",
                super::kind_label(&job.job_kind, language),
                super::job_state(job.state, language)
            ),
            crate::locale::format!(
                language,
                "Target: {}\nAttempt: {}",
                "目标：{}\n尝试次数：{}",
                job.target_revision,
                job.attempt
            ),
            crate::locale::format!(
                language,
                "End reason: {}",
                "结束原因：{}",
                super::job_reason(job.terminal_reason, language)
            ),
            crate::locale::format!(
                language,
                "Backoff until: {}\nLease until: {}",
                "退避截止：{}\n租约截止：{}",
                job.backoff_until_us.map_or_else(
                    || language.label("not supplied").to_owned(),
                    |value| timestamp(Some(value))
                ),
                job.lease_until_us.map_or_else(
                    || language.label("not supplied").to_owned(),
                    |value| timestamp(Some(value))
                )
            ),
            crate::locale::format!(
                language,
                "Result: {}",
                "结果：{}",
                job.terminal_result_ref
                    .as_deref()
                    .unwrap_or(state.language.label("No result reference supplied"))
            ),
            state
                .language
                .label("Start/end times not supplied; duration and ETA are unknown")
                .into(),
        ]);
        if let Some(backup) = &job.backup_summary {
            lines.extend([
                crate::locale::format!(
                    language,
                    "backup verification/frontier: {:?} / {}",
                    "备份验证／水位: {:?} / {}",
                    backup.validation_result,
                    backup.frontier
                ),
                crate::locale::format!(
                    language,
                    "Backup files: {}; bytes: {}",
                    "备份文件: {}; 字节: {}",
                    backup.file_count,
                    backup.total_bytes
                ),
            ]);
        }
        if let Some(gc) = &job.gc_summary {
            lines.push(crate::locale::format!(
                language,
                "GC deleted: {} files / {} bytes; unknown: {}",
                "回收已删除：{} 个文件／{} 字节；未知：{}",
                gc.deleted_count,
                gc.deleted_bytes,
                gc.unknown_count
            ));
        }
    } else {
        // These existing typed presenters preserve the protection/source labels and
        // domain facts. The generic identity preamble belongs to Technical.
        let content = super::content_lines(item, state.competing_candidate_selection, language);
        if content.is_empty() {
            lines.push(language.text(
                "This entry currently provides identity and status only; no typed readable body was supplied. Open Technical fields for the recorded facts; use System for collection and import diagnostics.",
                "此条目当前仅提供身份与状态，响应未提供可读正文。可在技术字段查看已有事实，或到系统页查看采集与导入诊断。",
            ).into());
        } else {
            lines.extend(content);
        }
    }
    lines.join("\n")
}
pub(crate) fn timestamp(value: Option<i64>) -> String {
    let Some(value) = value else {
        return "not supplied".into();
    };
    // Gregorian calendar, matching the repository's UTC session timestamp parser.
    let seconds = value.div_euclid(1_000_000);
    let mut days = seconds.div_euclid(86_400);
    if !(0..2_932_897).contains(&days) {
        return "outside supported calendar range (UTC)".into();
    }
    let leap = |year: i64| year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut year = 1970;
    while days >= if leap(year) { 366 } else { 365 } {
        days -= if leap(year) { 366 } else { 365 };
        year += 1;
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= months[month] {
        days -= months[month];
        month += 1;
    }
    let day_seconds = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        month + 1,
        days + 1,
        day_seconds / 3600,
        day_seconds / 60 % 60,
        day_seconds % 60
    )
}
fn changed(
    language: crate::Language,
    lines: &mut Vec<String>,
    label: &str,
    base: Option<&str>,
    candidate: &str,
    create: bool,
) {
    if base == Some(candidate) {
        return;
    }
    lines.push(format!(
        "{label}\n  {}\n→ {}",
        if create {
            language.label("New field (no base)").into()
        } else {
            base.map_or_else(
                || language.label("Original value unavailable").into(),
                super::safe_content,
            )
        },
        super::safe_content(candidate)
    ));
}

fn atom_fields(
    language: crate::Language,
    lines: &mut Vec<String>,
    draft: &evertrace_domain::semantic::AtomDraft,
    base: Option<&evertrace_domain::semantic::Atom>,
    create: bool,
) {
    changed(
        language,
        lines,
        language.label("Kind"),
        base.map(|a| format!("{:?}", a.kind)).as_deref(),
        &format!("{:?}", draft.kind),
        create,
    );
    changed(
        language,
        lines,
        language.label("Epistemic status"),
        base.map(|a| format!("{:?}", a.epistemic_status)).as_deref(),
        &format!("{:?}", draft.epistemic_status),
        create,
    );
    changed(
        language,
        lines,
        language.label("Text"),
        base.map(|a| a.value.text.as_str()),
        &draft.value.text,
        create,
    );
    changed(
        language,
        lines,
        language.label("Subject"),
        base.map(|a| a.value.subject.as_str()),
        &draft.value.subject,
        create,
    );
    changed(
        language,
        lines,
        language.label("Predicate"),
        base.map(|a| a.value.predicate.as_str()),
        &draft.value.predicate,
        create,
    );
    changed(
        language,
        lines,
        language.label("Object"),
        base.map(|a| a.value.object.as_deref().unwrap_or("not supplied")),
        draft.value.object.as_deref().unwrap_or("not supplied"),
        create,
    );
    changed(
        language,
        lines,
        language.label("Scope"),
        base.map(|a| format!("{:?}", a.scope)).as_deref(),
        &format!("{:?}", draft.scope),
        create,
    );
    changed(
        language,
        lines,
        language.label("Applicability"),
        base.map(|a| format!("{:?}", a.applicability_expr))
            .as_deref(),
        &format!("{:?}", draft.applicability_expr),
        create,
    );
    changed(
        language,
        lines,
        language.label("Validity"),
        base.map(|a| format!("{:?}", a.validity_interval))
            .as_deref(),
        &format!("{:?}", draft.validity_interval),
        create,
    );
}
fn procedure_fields(
    language: crate::Language,
    lines: &mut Vec<String>,
    draft: &evertrace_domain::procedure::ProcedureDraft,
    base: Option<&evertrace_domain::procedure::ProcedureDraft>,
    create: bool,
) {
    changed(
        language,
        lines,
        language.label("Scope"),
        base.map(|a| format!("{:?}", a.scope)).as_deref(),
        &format!("{:?}", draft.scope),
        create,
    );
    changed(
        language,
        lines,
        language.label("Applicability"),
        base.map(|a| format!("{:?}", a.applicability_expr))
            .as_deref(),
        &format!("{:?}", draft.applicability_expr),
        create,
    );
    changed(
        language,
        lines,
        language.label("Avoid condition"),
        base.map(|a| format!("{:?}", a.avoid_expr)).as_deref(),
        &format!("{:?}", draft.avoid_expr),
        create,
    );
    changed(
        language,
        lines,
        language.label("Completion condition"),
        base.map(|a| format!("{:?}", a.completion_expr)).as_deref(),
        &format!("{:?}", draft.completion_expr),
        create,
    );
    changed(
        language,
        lines,
        language.label("Branches"),
        base.map(|a| format!("{:?}", a.actions.branches)).as_deref(),
        &format!("{:?}", draft.actions.branches),
        create,
    );
    changed(
        language,
        lines,
        language.label("Abort"),
        base.map(|a| a.done.abort.join("; ")).as_deref(),
        &draft.done.abort.join("; "),
        create,
    );
    changed(
        language,
        lines,
        language.label("Verify"),
        base.map(|a| a.done.verify.join("; ")).as_deref(),
        &draft.done.verify.join("; "),
        create,
    );
    changed(
        language,
        lines,
        language.label("Title"),
        base.map(|b| b.title.as_str()),
        &draft.title,
        create,
    );
    changed(
        language,
        lines,
        language.label("Summary"),
        base.map(|b| b.summary.as_str()),
        &draft.summary,
        create,
    );
    changed(
        language,
        lines,
        language.label("When / stage"),
        base.map(|b| b.when.stage.as_str()),
        &draft.when.stage,
        create,
    );
    for (label, old, new) in [
        (
            language.label("Goals"),
            base.map(|b| &b.when.goals),
            &draft.when.goals,
        ),
        (
            language.label("Targets"),
            base.map(|b| &b.when.targets),
            &draft.when.targets,
        ),
        (
            language.label("Signals"),
            base.map(|b| &b.when.signals),
            &draft.when.signals,
        ),
        (
            language.label("Requires"),
            base.map(|b| &b.when.requires),
            &draft.when.requires,
        ),
        (
            language.label("Excludes"),
            base.map(|b| &b.when.excludes),
            &draft.when.excludes,
        ),
        (
            language.label("Do"),
            base.map(|b| &b.actions.stages),
            &draft.actions.stages,
        ),
        (
            language.label("Avoid"),
            base.map(|b| &b.actions.avoid),
            &draft.actions.avoid,
        ),
        (
            language.label("Done"),
            base.map(|b| &b.done.success),
            &draft.done.success,
        ),
        (
            language.label("Pitfalls"),
            base.map(|b| &b.pitfalls),
            &draft.pitfalls,
        ),
    ] {
        changed(
            language,
            lines,
            label,
            old.map(|v| v.join("; ")).as_deref(),
            &new.join("; "),
            create,
        );
    }
}
fn proposal_diff(item: &HumanSnapshotItem, language: crate::Language) -> Vec<String> {
    use evertrace_domain::semantic::{AtomProposalPayload, ProposalPayload};
    let review = item.proposal_review.as_ref().expect("proposal checked");
    let proposal = &review.proposal;
    let create = proposal.operation == evertrace_domain::semantic::ProposalOperation::Create;
    let base = item.proposal_base.as_ref().and_then(|b| b.content.as_ref());
    let mut lines = vec![
        crate::locale::format!(
            language,
            "Why here: {:?} proposal requires review ({:?})",
            "待处理原因：{:?} 提议需要复核（{:?}）",
            proposal.operation,
            proposal.status
        ),
        if create {
            language
                .label("Change: Create — new object, no base")
                .into()
        } else if base.is_none() {
            language.label("Original revision could not be read; comparison is incomplete. Existing actions remain governed by the daemon.").into()
        } else {
            language
                .label("Change: exact base → candidate; unchanged fields omitted")
                .into()
        },
    ];
    if !create
        && base.is_none()
        && let Some(b) = &item.proposal_base
    {
        lines.extend(super::semantic_lines(b, language));
    }
    match &proposal.payload {
        ProposalPayload::Atom(payload) => {
            let old = match base {
                Some(HumanSemanticContent::Atom(a)) => Some(a.as_ref()),
                _ => None,
            };
            match payload.as_ref() {
                AtomProposalPayload::Create { draft }
                | AtomProposalPayload::Replace { draft }
                | AtomProposalPayload::Reclassify { draft }
                | AtomProposalPayload::Merge { draft, .. } => {
                    atom_fields(language, &mut lines, draft, old, create)
                }
                AtomProposalPayload::Split { drafts } => {
                    for (i, draft) in drafts.iter().enumerate() {
                        lines.push(crate::locale::format!(
                            language,
                            "Candidate {}",
                            "候选 {}",
                            i + 1
                        ));
                        atom_fields(language, &mut lines, draft, old, create);
                    }
                }
                AtomProposalPayload::Deprecate { reason } => lines.push(crate::locale::format!(
                    language,
                    "Remove from active use\nReason: {}",
                    "从当前使用中移除\n原因：{}",
                    super::safe_content(reason)
                )),
            }
        }
        ProposalPayload::Procedure(payload) => {
            let old = match base {
                Some(HumanSemanticContent::Procedure(p)) => Some(&p.draft),
                _ => None,
            };
            procedure_fields(language, &mut lines, payload.draft(), old, create);
        }
        ProposalPayload::CoreMembership(payload) => {
            use evertrace_domain::semantic::CoreMembershipProposalPayload;
            let old = match base {
                Some(HumanSemanticContent::CoreMembership(m)) => Some(m.as_ref()),
                _ => None,
            };
            let old_atom = old.map(|m| m.atom_revision_id.to_string());
            let old_scope = old.map(|m| format!("{:?}", m.scope_identity));
            let scope = match payload.as_ref() {
                CoreMembershipProposalPayload::Create {
                    atom_revision_id,
                    scope_identity,
                } => {
                    changed(
                        language,
                        &mut lines,
                        language.label("Atom revision"),
                        old_atom.as_deref(),
                        &atom_revision_id.to_string(),
                        create,
                    );
                    scope_identity
                }
                CoreMembershipProposalPayload::ResolveConflict {
                    left_atom_revision_id,
                    right_atom_revision_id,
                    scope_identity,
                } => {
                    changed(
                        language,
                        &mut lines,
                        language.label("Conflict left atom revision"),
                        old_atom.as_deref(),
                        &left_atom_revision_id.to_string(),
                        create,
                    );
                    changed(
                        language,
                        &mut lines,
                        language.label("Conflict right atom revision"),
                        old_atom.as_deref(),
                        &right_atom_revision_id.to_string(),
                        create,
                    );
                    lines.push(language.label("Conflict pair is the requested resolution input, not an inferred winning revision").into());
                    scope_identity
                }
            };
            changed(
                language,
                &mut lines,
                language.label("Scope identity"),
                old_scope.as_deref(),
                &format!("{scope:?}"),
                create,
            );
        }
        ProposalPayload::ReservedTarget { summary, .. } => lines.push(super::safe_content(summary)),
    }
    lines.push(
        language.label("Known impact: a new revision if applied; impact counts not provided, not estimated").into(),
    );
    lines.push(crate::locale::format!(language, "Conditions\nEligibility: {:?}\nAccept: {}\nMerge: {}\nEvidence references: {} (open sources to inspect)", "条件\n资格：{:?}\n接受：{}\n合并：{}\n证据引用：{}（打开来源查看）",proposal.eligibility,
        if review.plain_accept_eligible{language.label("allowed by current daemon review")}else{language.label("blocked by existing eligibility conditions")},
        if review.merge_and_accept_eligible{language.label("allowed by current daemon review")}else{language.label("not eligible")},proposal.evidence_refs.len()));
    lines
}

#[cfg(test)]
mod calendar_tests {
    use super::timestamp;
    #[test]
    fn utc_calendar_handles_epoch_leap_day_and_unknown() {
        assert_eq!(timestamp(None), "not supplied");
        assert_eq!(timestamp(Some(0)), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            timestamp(Some(951_827_696_000_000)),
            "2000-02-29 12:34:56 UTC"
        );
        assert_eq!(
            timestamp(Some(i64::MAX)),
            "outside supported calendar range (UTC)"
        );
    }
}
