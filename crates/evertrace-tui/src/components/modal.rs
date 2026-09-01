use crate::theme::EVER_OS;
use ratatui::{
    style::Style,
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn modal(body: String) -> (Clear, Paragraph<'static>) {
    (
        Clear,
        Paragraph::new(body)
            .style(Style::default().fg(EVER_OS.amber).bg(EVER_OS.raised))
            .block(Block::default().title("EverTrace").borders(Borders::ALL)),
    )
}
