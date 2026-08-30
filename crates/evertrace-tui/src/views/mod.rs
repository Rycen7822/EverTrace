mod explorer;
mod inbox;
mod system;
use crate::Route;
use ratatui::{Frame, layout::Rect};
pub fn render(f: &mut Frame, a: Rect, r: Route) {
    match r {
        Route::Inbox => inbox::render(f, a),
        Route::Explorer => explorer::render(f, a),
        Route::System => system::render(f, a),
    }
}
