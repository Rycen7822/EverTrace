use crate::components;
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect) {
    f.render_widget(components::table("Inbox", "No inbox items"), a)
}
