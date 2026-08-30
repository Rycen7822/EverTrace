use ratatui::widgets::{Block, Borders, Paragraph};
pub fn inspector() -> Paragraph<'static> {
    Paragraph::new("Select an item")
        .block(Block::default().title("Inspector").borders(Borders::ALL))
}
