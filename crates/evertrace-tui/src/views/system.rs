use crate::{AppState, components};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    let in_detail = state.detail.is_some() || state.detail_message.is_some();
    let mut body = crate::views::page_body(state, "No current system projection facts");
    if !in_detail {
        if let Some(health) = &state.shell.health {
            match &health.host_canary {
                Some(value) => body.push_str(&format!(
                    "\nHost canary: {:?}\nNative delivery: {}\nMCP consumed: {}\nCaptureReceipt: {}",
                    value.status, value.native_delivery_observed,
                    value.mcp_claim_consumed, value.capture_receipt_observed,
                )),
                None => body.push_str("\nHost canary: not_run"),
            }
            body.push_str("\nCapability qualification is independent");
        }
        body.push_str(
            "\nObject Forget: available in Explorer\nRepository/session purge: unavailable\nBackup create/verify: durable jobs (B/V)\nGC + normal prune (G): 24 h grace / 30 d versions\nRestore: offline CLI only\nConfiguration write: unavailable",
        );
    }
    f.render_widget(
        components::table("System", body).scroll((state.detail_scroll, 0)),
        a,
    )
}
