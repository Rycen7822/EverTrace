use crate::theme::EVER_OS;
use ratatui::{
    style::Style,
    widgets::{Block, Borders, Paragraph},
};

pub fn table(title: &'static str, body: String) -> Paragraph<'static> {
    Paragraph::new(body)
        .style(Style::default().fg(EVER_OS.muted))
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(EVER_OS.border)),
        )
}
