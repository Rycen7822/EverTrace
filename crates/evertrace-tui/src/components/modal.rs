use crate::theme::EVER_OS;
use ratatui::{
    style::Style,
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn modal() -> (Clear, Paragraph<'static>) {
    (
        Clear,
        Paragraph::new("Request pending")
            .style(Style::default().fg(EVER_OS.amber).bg(EVER_OS.raised))
            .block(Block::default().title("EverTrace").borders(Borders::ALL)),
    )
}
