use ratatui::widgets::{Block, Borders, Paragraph};
pub fn inspector(body: String) -> Paragraph<'static> {
    Paragraph::new(body).block(Block::default().title("Inspector").borders(Borders::ALL))
}
