use crate::theme::EVER_OS;
use crate::{ConnectionState, ShellSnapshot};
use ratatui::{
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
pub fn status_bar(s: &ShellSnapshot) -> Paragraph<'static> {
    let (text, color) = match s.connection {
        ConnectionState::Connected => ("● connected", EVER_OS.green),
        ConnectionState::Connecting => ("◌ connecting", EVER_OS.cyan),
        ConnectionState::Disconnected => ("! disconnected", EVER_OS.red),
        ConnectionState::ServerStopping => ("! server stopping", EVER_OS.amber),
    };
    Paragraph::new(Line::from(vec![
        Span::styled(text, Style::default().fg(color)),
        Span::raw(format!(" pending:{}", s.pending)),
    ]))
}
