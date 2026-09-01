use crate::{AppState, components};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    let body = if state.detail.is_some() || state.detail_message.is_some() {
        crate::views::page_body(state, "No objects loaded")
    } else {
        state.recovery_result.as_ref().map_or_else(
            || crate::views::page_body(state, "No objects loaded"),
            |result| {
                format!(
                    "recovery: {}{}",
                    result
                        .application_status
                        .map_or("unavailable".into(), |status| format!("{status:?}")),
                    result
                        .unsupported_reason
                        .map_or(String::new(), |reason| format!(" ({reason:?})"))
                )
            },
        )
    };
    f.render_widget(
        components::table("Explorer", body).scroll((state.detail_scroll, 0)),
        a,
    )
}
