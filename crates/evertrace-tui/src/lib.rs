#![forbid(unsafe_code)]
#![deny(warnings)]

mod app;
mod app_event;
mod client;
mod command;
mod components;
mod event_sender;
mod keymap;
mod layout;
mod state;
mod terminal;
mod theme;
mod views;

pub use app::{App, headless_render, run};
pub use app_event::{AppEvent, HumanReadLocator};
pub use command::UiCommand;
pub use event_sender::AppEventSender;
pub use state::{AppState, ConnectionState, Route, ShellSnapshot};
pub use terminal::TerminalGuard;
