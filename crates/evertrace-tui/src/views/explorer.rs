use crate::AppState;
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    super::render_list(
        f,
        a,
        state,
        match state.ui.explorer_selection {
            Some(evertrace_protocol::dto::HumanExplorerListSelection::Memories) => state
                .language
                .text("Explorer · memory results", "浏览 · 记忆结果"),
            Some(evertrace_protocol::dto::HumanExplorerListSelection::Capture) => state
                .language
                .text("Explorer · capture records", "浏览 · 采集记录"),
            None => state.language.text("Explorer · all records", "浏览 · 全部"),
        },
    );
}
