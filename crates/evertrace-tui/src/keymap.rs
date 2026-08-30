use crate::{Route, UiCommand};
use crossterm::event::{KeyCode, KeyEvent};
pub fn command(k: KeyEvent) -> UiCommand {
    match k.code {
        KeyCode::Char('q') => UiCommand::Quit,
        KeyCode::Char('1') => UiCommand::Navigate(Route::Inbox),
        KeyCode::Char('2') => UiCommand::Navigate(Route::Explorer),
        KeyCode::Char('3') => UiCommand::Navigate(Route::System),
        KeyCode::Char('r') => UiCommand::Refresh,
        _ => UiCommand::None,
    }
}
