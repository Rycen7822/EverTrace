use crate::{AppState, components};
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    f.render_widget(
        components::table("Inbox", crate::views::page_body(state, "No inbox items"))
            .scroll((state.detail_scroll, 0)),
        a,
    )
}
