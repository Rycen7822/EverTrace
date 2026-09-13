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
    let Some(item) = state.detail.as_ref() else {
        return "Open an item to read its content".into();
    };
    if state.ui.detail_view == DetailView::Technical {
        return super::inspector_text(state);
    }
    let mut lines = vec![
        super::row_label(item),
        format!(
            "Selected revision · scope: {}",
            item.scope_ref.as_deref().unwrap_or("not supplied")
        ),
    ];
    if item.proposal_review.is_some() {
        lines.extend(proposal_diff(item));
        return lines.join("\n");
    }
    if let Some(semantic) = &item.semantic_detail {
        lines.extend(super::semantic_lines(semantic));
    } else if let Some(HumanSystemDetail::Job { detail: job }) = &item.system_detail {
        lines.extend([
            format!(
                "Task: {}\nState: {:?} (leased means claimed, not a model call)",
                job.job_kind, job.state
            ),
            format!("Target: {}\nAttempt: {}", job.target_revision, job.attempt),
            format!(
                "End reason: {}",
                job.terminal_reason
                    .map_or_else(|| "not supplied".into(), |r| format!("{r:?}"))
            ),
            format!(
                "Backoff until: {}\nLease until: {}",
                timestamp(job.backoff_until_us),
                timestamp(job.lease_until_us)
            ),
            format!(
                "Result: {}",
                job.terminal_result_ref
                    .as_deref()
                    .unwrap_or("No result reference supplied")
            ),
            "Start/end times not supplied; duration and ETA are unknown".into(),
        ]);
        if let Some(backup) = &job.backup_summary {
            lines.extend([
                format!(
                    "backup verification/frontier: {:?} / {}",
                    backup.validation_result, backup.frontier
                ),
                format!(
                    "Backup files: {}; bytes: {}",
                    backup.file_count, backup.total_bytes
                ),
            ]);
        }
        if let Some(gc) = &job.gc_summary {
            lines.push(format!(
                "GC deleted: {} files / {} bytes; unknown: {}",
                gc.deleted_count, gc.deleted_bytes, gc.unknown_count
            ));
        }
    } else {
        // These existing typed presenters preserve the protection/source labels and
        // domain facts. The generic identity preamble belongs to Technical.
        lines.extend(super::content_lines(
            item,
            state.competing_candidate_selection,
        ));
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
            "New field (no base)".into()
        } else {
            base.map_or_else(|| "Original value unavailable".into(), super::safe_content)
        },
        super::safe_content(candidate)
    ));
}

fn atom_fields(
    lines: &mut Vec<String>,
    draft: &evertrace_domain::semantic::AtomDraft,
    base: Option<&evertrace_domain::semantic::Atom>,
    create: bool,
) {
    changed(
        lines,
        "Kind",
        base.map(|a| format!("{:?}", a.kind)).as_deref(),
        &format!("{:?}", draft.kind),
        create,
    );
    changed(
        lines,
        "Epistemic status",
        base.map(|a| format!("{:?}", a.epistemic_status)).as_deref(),
        &format!("{:?}", draft.epistemic_status),
        create,
    );
    changed(
        lines,
        "Text",
        base.map(|a| a.value.text.as_str()),
        &draft.value.text,
        create,
    );
    changed(
        lines,
        "Subject",
        base.map(|a| a.value.subject.as_str()),
        &draft.value.subject,
        create,
    );
    changed(
        lines,
        "Predicate",
        base.map(|a| a.value.predicate.as_str()),
        &draft.value.predicate,
        create,
    );
    changed(
        lines,
        "Object",
        base.map(|a| a.value.object.as_deref().unwrap_or("not supplied")),
        draft.value.object.as_deref().unwrap_or("not supplied"),
        create,
    );
    changed(
        lines,
        "Scope",
        base.map(|a| format!("{:?}", a.scope)).as_deref(),
        &format!("{:?}", draft.scope),
        create,
    );
    changed(
        lines,
        "Applicability",
        base.map(|a| format!("{:?}", a.applicability_expr))
            .as_deref(),
        &format!("{:?}", draft.applicability_expr),
        create,
    );
    changed(
        lines,
        "Validity",
        base.map(|a| format!("{:?}", a.validity_interval))
            .as_deref(),
        &format!("{:?}", draft.validity_interval),
        create,
    );
}
fn procedure_fields(
    lines: &mut Vec<String>,
    draft: &evertrace_domain::procedure::ProcedureDraft,
    base: Option<&evertrace_domain::procedure::ProcedureDraft>,
    create: bool,
) {
    changed(
        lines,
        "Scope",
        base.map(|a| format!("{:?}", a.scope)).as_deref(),
        &format!("{:?}", draft.scope),
        create,
    );
    changed(
        lines,
        "Applicability",
        base.map(|a| format!("{:?}", a.applicability_expr))
            .as_deref(),
        &format!("{:?}", draft.applicability_expr),
        create,
    );
    changed(
        lines,
        "Avoid condition",
        base.map(|a| format!("{:?}", a.avoid_expr)).as_deref(),
        &format!("{:?}", draft.avoid_expr),
        create,
    );
    changed(
        lines,
        "Completion condition",
        base.map(|a| format!("{:?}", a.completion_expr)).as_deref(),
        &format!("{:?}", draft.completion_expr),
        create,
    );
    changed(
        lines,
        "Branches",
        base.map(|a| format!("{:?}", a.actions.branches)).as_deref(),
        &format!("{:?}", draft.actions.branches),
        create,
    );
    changed(
        lines,
        "Abort",
        base.map(|a| a.done.abort.join("; ")).as_deref(),
        &draft.done.abort.join("; "),
        create,
    );
    changed(
        lines,
        "Verify",
        base.map(|a| a.done.verify.join("; ")).as_deref(),
        &draft.done.verify.join("; "),
        create,
    );
    changed(
        lines,
        "Title",
        base.map(|b| b.title.as_str()),
        &draft.title,
        create,
    );
    changed(
        lines,
        "Summary",
        base.map(|b| b.summary.as_str()),
        &draft.summary,
        create,
    );
    changed(
        lines,
        "When / stage",
        base.map(|b| b.when.stage.as_str()),
        &draft.when.stage,
        create,
    );
    for (label, old, new) in [
        ("Goals", base.map(|b| &b.when.goals), &draft.when.goals),
        (
            "Targets",
            base.map(|b| &b.when.targets),
            &draft.when.targets,
        ),
        (
            "Signals",
            base.map(|b| &b.when.signals),
            &draft.when.signals,
        ),
        (
            "Requires",
            base.map(|b| &b.when.requires),
            &draft.when.requires,
        ),
        (
            "Excludes",
            base.map(|b| &b.when.excludes),
            &draft.when.excludes,
        ),
        ("Do", base.map(|b| &b.actions.stages), &draft.actions.stages),
        (
            "Avoid",
            base.map(|b| &b.actions.avoid),
            &draft.actions.avoid,
        ),
        ("Done", base.map(|b| &b.done.success), &draft.done.success),
        ("Pitfalls", base.map(|b| &b.pitfalls), &draft.pitfalls),
    ] {
        changed(
            lines,
            label,
            old.map(|v| v.join("; ")).as_deref(),
            &new.join("; "),
            create,
        );
    }
}
fn proposal_diff(item: &HumanSnapshotItem) -> Vec<String> {
    use evertrace_domain::semantic::{AtomProposalPayload, ProposalPayload};
    let review = item.proposal_review.as_ref().expect("proposal checked");
    let proposal = &review.proposal;
    let create = proposal.operation == evertrace_domain::semantic::ProposalOperation::Create;
    let base = item.proposal_base.as_ref().and_then(|b| b.content.as_ref());
    let mut lines = vec![
        format!(
            "Why here: {:?} proposal requires review ({:?})",
            proposal.operation, proposal.status
        ),
        if create {
            "Change: Create — new object, no base".into()
        } else if base.is_none() {
            "Original revision could not be read; comparison is incomplete. Existing actions remain governed by the daemon.".into()
        } else {
            "Change: exact base → candidate; unchanged fields omitted".into()
        },
    ];
    if !create
        && base.is_none()
        && let Some(b) = &item.proposal_base
    {
        lines.extend(super::semantic_lines(b));
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
                    atom_fields(&mut lines, draft, old, create)
                }
                AtomProposalPayload::Split { drafts } => {
                    for (i, draft) in drafts.iter().enumerate() {
                        lines.push(format!("Candidate {}", i + 1));
                        atom_fields(&mut lines, draft, old, create);
                    }
                }
                AtomProposalPayload::Deprecate { reason } => lines.push(format!(
                    "Remove from active use\nReason: {}",
                    super::safe_content(reason)
                )),
            }
        }
        ProposalPayload::Procedure(payload) => {
            let old = match base {
                Some(HumanSemanticContent::Procedure(p)) => Some(&p.draft),
                _ => None,
            };
            procedure_fields(&mut lines, payload.draft(), old, create);
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
                        &mut lines,
                        "Atom revision",
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
                        &mut lines,
                        "Conflict left atom revision",
                        old_atom.as_deref(),
                        &left_atom_revision_id.to_string(),
                        create,
                    );
                    changed(
                        &mut lines,
                        "Conflict right atom revision",
                        old_atom.as_deref(),
                        &right_atom_revision_id.to_string(),
                        create,
                    );
                    lines.push("Conflict pair is the requested resolution input, not an inferred winning revision".into());
                    scope_identity
                }
            };
            changed(
                &mut lines,
                "Scope identity",
                old_scope.as_deref(),
                &format!("{scope:?}"),
                create,
            );
        }
        ProposalPayload::ReservedTarget { summary, .. } => lines.push(super::safe_content(summary)),
    }
    lines.push(
        "Known impact: a new revision if applied; impact counts not provided, not estimated".into(),
    );
    lines.push(format!("Conditions\nEligibility: {:?}\nAccept: {}\nMerge: {}\nEvidence references: {} (open sources to inspect)",proposal.eligibility,
        if review.plain_accept_eligible{"allowed by current daemon review"}else{"blocked by existing eligibility conditions"},
        if review.merge_and_accept_eligible{"allowed by current daemon review"}else{"not eligible"},proposal.evidence_refs.len()));
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
