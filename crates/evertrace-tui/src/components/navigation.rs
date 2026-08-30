use crate::Route;
use crate::theme::EVER_OS;
use ratatui::{
    style::Style,
    widgets::{Block, Borders, Paragraph},
};
pub fn navigation(r: Route) -> Paragraph<'static> {
    Paragraph::new(match r {
        Route::Inbox => "> Inbox\n  Explorer\n  System",
        Route::Explorer => "  Inbox\n> Explorer\n  System",
        Route::System => "  Inbox\n  Explorer\n> System",
    })
    .style(Style::default().fg(EVER_OS.cyan))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(EVER_OS.border)),
    )
}
