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
    let mut paragraph = components::table("Explorer", body).scroll((state.detail_scroll, 0));
    if state
        .detail
        .as_ref()
        .is_some_and(|item| item.evidence_detail.is_some() || item.work_detail.is_some())
    {
        paragraph = paragraph.wrap(ratatui::widgets::Wrap { trim: false });
    }
    f.render_widget(paragraph, a)
}
