use crate::{AppState, state::SystemView};
use evertrace_protocol::dto::{HumanGovernanceResponse, HumanSystemDetail};
use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Paragraph, Wrap},
};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    let report = match &state.human {
        Some(HumanGovernanceResponse::Snapshot { diagnostics, .. }) => diagnostics.as_deref(),
        _ => None,
    };
    match state.ui.system_view {
        SystemView::Overview => {
            let count = |name: &str| {
                report
                    .and_then(|r| r.checks.iter().find(|c| c.name == name))
                    .and_then(|c| c.count)
                    .map_or_else(|| "not read".into(), |n| n.to_string())
            };
            let capture = report.and_then(|r| r.host.as_ref()).map_or_else(
                || {
                    state
                        .shell
                        .health
                        .as_ref()
                        .and_then(|h| h.host_canary.as_ref())
                        .map_or_else(
                            || "Hook: not observed".into(),
                            |h| {
                                format!(
                                    "Last Health: Host canary: {:?}; CaptureReceipt: {}",
                                    h.status, h.capture_receipt_observed
                                )
                            },
                        )
                },
                |h| {
                    format!(
                        "Hook: {:?}; receipt observed: {}",
                        h.status, h.capture_receipt_observed
                    )
                },
            );
            let provider = report
                .and_then(|r| r.checks.iter().find(|c| c.name == "provider_connectivity"))
                .map_or_else(|| "not checked".into(), |c| format!("{:?}", c.state));
            let water = report.map_or_else(
                || "Projection watermarks: not read".into(),
                |r| {
                    format!(
                        "Projection checkpoints: {} · metadata only",
                        r.tables
                            .iter()
                            .map(|t| t
                                .checkpoint
                                .map_or_else(|| "unknown".into(), |n| n.to_string()))
                            .collect::<Vec<_>>()
                            .join(" / ")
                    )
                },
            );
            let body = format!(
                "{capture}\nQueued {} · Leased {} · Historical failures {}\nModel: {provider} (no probe); recorded calls {}\n{water}",
                count("jobs_queued"),
                count("jobs_leased"),
                count("jobs_failed_history"),
                count("llm_daily_calls")
            );
            let height = a.height.min(5);
            f.render_widget(Paragraph::new(body), Rect::new(a.x, a.y, a.width, height));
            super::render_list(
                f,
                Rect::new(a.x, a.y + height, a.width, a.height - height),
                state,
                "Tasks · current page (leased = claimed)",
            );
        }
        SystemView::Jobs => {
            super::render_list(f, a, state, "Tasks · name / state / target / reason")
        }
        SystemView::Diagnostics => {
            if state.ui.diagnostic_detail {
                let body=report.and_then(|r|r.checks.get(state.ui.diagnostic_selection).map(|c|(r,c))).map_or_else(||"Selected diagnostic is no longer available; Esc returns".into(),|(r,c)|format!("Check: {}\nObserved state: {:?}\nRecorded value: {}\nLimit: {}\nSample: {} microseconds since Unix epoch (UTC)\nScope: existing local diagnostic report, non-atomic.\nNotChecked means no check was executed; Historical is not a current failure.\nMetadata does not verify content integrity. This view never starts a provider probe.\nEsc returns to the same diagnostic row.",c.name,c.state,c.count.map_or_else(||"not supplied".into(),|v|v.to_string()),c.limit.map_or_else(||"not supplied".into(),|v|v.to_string()),r.observed_at_us));
                f.render_widget(
                    crate::components::table("Diagnostic detail", body)
                        .wrap(Wrap { trim: false })
                        .scroll((state.detail_scroll, 0)),
                    a,
                );
                return;
            }
            let body=report.map_or_else(||"Diagnostics not yet read".into(),|r|{
                let mut lines=vec![format!("Diagnostics sampled at {} microseconds since Unix epoch (UTC); non-atomic",r.observed_at_us),
                    "Metadata is not content verification; terminal failures are history.".into(),
                    "Provider NotChecked does not mean healthy; this view never calls the model.".into()];
                for (index,c) in r.checks.iter().enumerate().filter(|(_,c)|c.name.to_lowercase().contains(&state.ui.filter.to_lowercase())) {lines.push(format!("{} {} | {:?} | recorded {} | limit {}",if index==state.ui.diagnostic_selection{">"}else{" "},c.name,c.state,c.count.map_or_else(||"not supplied".into(),|v|v.to_string()),c.limit.map_or_else(||"not supplied".into(),|v|v.to_string())));}
                for (name,t) in ["journal","objects","relations","search"].into_iter().zip(&r.tables){lines.push(format!("{name}: version {:?}; checkpoint {:?}; schema {:?}",t.version,t.checkpoint,t.schema_matches));}
                if let Some(h)=&r.host {lines.push(format!("Host canary: {:?}; CaptureReceipt: {}; native delivery: {}; MCP consumed: {}",h.status,h.capture_receipt_observed,h.native_delivery_observed,h.mcp_claim_consumed));} else {lines.push("Host canary: not_run".into());}
                lines.join("\n")
            });
            f.render_widget(
                crate::components::table("Capture / storage / model diagnostics", body)
                    .scroll((state.detail_scroll, 0))
                    .wrap(Wrap { trim: false }),
                a,
            );
        }
        SystemView::Configuration => {
            let mut body="Configuration is read and written through the daemon.\nUse : Edit configuration to read the existing document.\nSaving uses its file hash; failed saves preserve the draft.\nRestartRequired means restart is needed; TUI does not restart the service.".to_string();
            if let Some(HumanGovernanceResponse::Snapshot { items, .. }) = &state.human {
                for i in items {
                    if let Some(HumanSystemDetail::Config {
                        config_version,
                        effective_config_hash,
                        reload,
                    }) = &i.system_detail
                    {
                        body.push_str(&format!(
                            "\nConfig version: {config_version}\nEffective hash: {}\nReload: {}",
                            super::short(&evertrace_domain::evidence::hex(effective_config_hash)),
                            reload.as_ref().map_or_else(
                                || "not supplied".into(),
                                |r| format!("{:?}", r.outcome)
                            )
                        ));
                    }
                }
            }
            f.render_widget(
                crate::components::table("Configuration", body).wrap(Wrap { trim: false }),
                a,
            );
        }
        SystemView::Maintenance => {
            let mut body = format!(
                "Export selection: {} objects (maximum 64).\nSelect objects in Explorer, then : Export selected objects.\nBackup / verification / GC submit durable jobs.\nRestore requires stopping the service and using the offline CLI.",
                state.export_selections.len()
            );
            if let Some(r) = &state.export_result {
                body.push_str(&format!(
                    "\nExport {:?}: {} objects / {} bytes\n{}\n{}",
                    r.status,
                    r.object_count,
                    r.total_bytes,
                    r.path.as_deref().unwrap_or("No confirmed published path"),
                    r.reason.as_deref().unwrap_or("")
                ));
            }
            f.render_widget(
                Paragraph::new(body).wrap(Wrap { trim: false }),
                Rect::new(a.x, a.y, a.width, a.height.min(7)),
            );
            if a.height > 7 {
                super::render_list(
                    f,
                    Rect::new(a.x, a.y + 7, a.width, a.height - 7),
                    state,
                    "Maintenance / repository facts · current page",
                );
            }
        }
    }
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
        let mut state = AppState {
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
        state.ui.system_view = SystemView::Diagnostics;
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
        assert!(text.contains("fts_metadata | Inconsistent"));
        assert!(text.contains("llm_daily_calls | Exhausted"));
        assert!(text.contains("Host canary: not_run"));
        let source = "session-rollout:019d0000-0000-7000-8000-000000000001:019d0000-0000-7000-8000-000000000002";
        use evertrace_protocol::dto::{
            HumanItemCategory, HumanItemKind, HumanObjectFamily, HumanRowClass, HumanSnapshotItem,
            HumanSystemDetail,
        };
        let item = HumanSnapshotItem {
            semantic_detail: None,
            proposal_base: None,
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
                repository_read_restrictions: Some(Vec::new()),
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
            .draw(|frame| {
                frame.render_widget(
                    Paragraph::new(crate::views::detail_text(&state)).wrap(Wrap { trim: false }),
                    frame.area(),
                )
            })
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
        let mut state = AppState {
            route: crate::Route::System,
            export_result: Some(evertrace_protocol::dto::HumanExportResult {
                status: evertrace_protocol::dto::HumanExportStatus::Published,
                path: Some("/private/data/exports/export-selected".into()),
                frontier: 9,
                object_count: 2,
                total_bytes: 100_001,
                reason: None,
            }),
            ..AppState::default()
        };
        state.ui.system_view = SystemView::Maintenance;
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
        assert!(text.contains("Export Published: 2 objects / 100001 bytes"));
        assert!(text.contains("/private/data/exports/export-selected"));
    }
}
