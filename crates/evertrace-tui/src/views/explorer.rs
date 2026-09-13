use crate::AppState;
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    super::render_list(
        f,
        a,
        state,
        state.language.text(
            "Explorer · type / reference / state / scope",
            "浏览 · 类型／引用／状态／范围",
        ),
    );
}
