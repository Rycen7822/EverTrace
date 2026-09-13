use crate::AppState;
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, state: &AppState) {
    super::render_list(f, a, state, "Explorer · type / reference / state / scope");
}
