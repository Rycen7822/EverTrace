use crate::{AppState, components};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    let in_detail = state.detail.is_some() || state.detail_message.is_some();
    let mut body = crate::views::page_body(state, "No current system projection facts");
    if !in_detail {
        body.push_str(
            "\nObject Forget: available in Explorer\nRepository/session purge: unavailable\nBackup/restore/GC: offline CLI or unavailable (S33)\nConfiguration write: unavailable",
        );
    }
    f.render_widget(
        components::table("System", body).scroll((state.detail_scroll, 0)),
        a,
    )
}
