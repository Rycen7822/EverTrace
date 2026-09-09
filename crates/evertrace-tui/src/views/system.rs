use crate::{AppState, components};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    let in_detail = state.detail.is_some() || state.detail_message.is_some();
    let mut body = crate::views::page_body(state, "No current system projection facts");
    if !in_detail {
        if let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
            diagnostics: Some(report),
            ..
        }) = &state.human
        {
            body.push_str(&format!("\nCurrent diagnostics (non-atomic; j/k scroll)\nconfig={}\nobserved_us={} algorithm_revision={}", report.config_hash, report.observed_at_us, report.algorithm_revision));
            for (name, table) in ["journal", "objects", "relations", "search"]
                .into_iter()
                .zip(&report.tables)
            {
                body.push_str(&format!(
                    "\n{name}: schema={:?} version={:?} checkpoint={:?}",
                    table.schema_matches, table.version, table.checkpoint
                ));
            }
            for check in &report.checks {
                body.push_str(&format!(
                    "\n{}: {:?} recorded={:?} limit={:?}",
                    check.name, check.state, check.count, check.limit
                ));
            }
            body.push_str("\nMetadata is not content verification; terminal failures are history.\nDaily usage does not predict next-request eligibility.");
            append_canary(&mut body, report.host.as_ref());
        } else {
            body.push_str("\nCurrent diagnostics: unavailable");
            if let Some(health) = &state.shell.health {
                body.push_str("\nLast Health observation (not a current diagnostic report)");
                append_canary(&mut body, health.host_canary.as_ref());
            }
        }
        body.push_str(
            "\nObject Forget: available in Explorer\nRepository/session purge: unavailable\nBackup create/verify: durable jobs (B/V)\nGC + normal prune (G): 24 h grace / 30 d versions\nRestore: offline CLI only\nConfiguration write: unavailable",
        );
    }
    let mut widget = components::table("System", body).scroll((state.detail_scroll, 0));
    if state.detail.as_ref().is_some_and(|item| {
        matches!(
            item.system_detail,
            Some(evertrace_protocol::dto::HumanSystemDetail::SessionImport { .. })
        )
    }) {
        widget = widget.wrap(ratatui::widgets::Wrap { trim: false });
    }
    f.render_widget(widget, a)
}

fn append_canary(
    body: &mut String,
    canary: Option<&evertrace_protocol::dto::HostCanaryDiagnostic>,
) {
    match canary {
        Some(value) => body.push_str(&format!(
            "\nHost canary: {:?}\nNative delivery: {}\nMCP consumed: {}\nCaptureReceipt: {}",
            value.status,
            value.native_delivery_observed,
            value.mcp_claim_consumed,
            value.capture_receipt_observed,
        )),
        None => body.push_str("\nHost canary: not_run"),
    }
    body.push_str("\nCapability qualification is independent");
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_protocol::dto::{
        HumanDiagnosticCheck, HumanDiagnosticState, HumanDiagnostics, HumanGovernanceResponse,
        HumanSnapshotStatus, HumanTableDiagnostic,
    };

    #[test]
    fn system_renders_current_checks_without_health_or_synthetic_objects() {
        let report = HumanDiagnostics {
            config_version: 1,
            algorithm_revision: 1,
            config_hash: "ab".repeat(32),
            observed_at_us: 1,
            tables: (0..4)
                .map(|_| HumanTableDiagnostic {
                    schema_matches: Some(true),
                    version: Some(2),
                    checkpoint: Some(4),
                })
                .collect(),
            checks: vec![
                HumanDiagnosticCheck {
                    name: "fts_metadata".into(),
                    state: HumanDiagnosticState::Inconsistent,
                    count: None,
                    limit: None,
                },
                HumanDiagnosticCheck {
                    name: "llm_daily_calls".into(),
                    state: HumanDiagnosticState::Exhausted,
                    count: Some(5),
                    limit: Some(5),
                },
            ],
            host: None,
        };
        assert!(report.validate());
        let state = AppState {
            route: crate::Route::System,
            human: Some(HumanGovernanceResponse::Snapshot {
                diagnostics: Some(Box::new(report)),
                frontier: 4,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![],
                next_cursor: None,
            }),
            ..AppState::default()
        };
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 40)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("fts_metadata: Inconsistent"));
        assert!(text.contains("llm_daily_calls: Exhausted"));
        assert!(text.contains("Host canary: not_run"));
        let source = "session-rollout:019d0000-0000-7000-8000-000000000001:019d0000-0000-7000-8000-000000000002";
        use evertrace_protocol::dto::{
            HumanItemCategory, HumanItemKind, HumanObjectFamily, HumanRowClass, HumanSnapshotItem,
            HumanSystemDetail,
        };
        let item = HumanSnapshotItem {
            evidence_detail: None,
            work_detail: None,
            item_kind: HumanItemKind::Generic,
            proposal: None,
            proposal_review: None,
            support_detail: None,
            competing_detail: None,
            forget_preview: None,
            repository_purge_preview: None,
            negative_review: None,
            recovery_detail: None,
            worktree_detail: None,
            execution_integrity_detail: None,
            system_detail: Some(HumanSystemDetail::SessionImport {
                session_id: "019d0000-0000-7000-8000-000000000001".into(),
                source_instance_id: source.into(),
                body_state: "Partial".into(),
                access: "Approved".into(),
                workspace: "NonRepository".into(),
            }),
            stable_key: format!("runtime:session_import:{source}"),
            row_class: HumanRowClass::Runtime,
            family: HumanObjectFamily::Runtime,
            category: HumanItemCategory::SessionImport,
            object_kind: "session_import_current".into(),
            object_ref: None,
            revision_ref: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            scope_ref: None,
            source_event_seq: 1,
        };
        let state = AppState {
            detail: Some(item),
            ..AppState::default()
        };
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains(source));
        assert!(text.contains("body: Partial"));
        assert!(text.contains("access: Approved; workspace: NonRepository"));
    }
}
