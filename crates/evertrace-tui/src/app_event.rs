use crossterm::event::KeyEvent;
use evertrace_protocol::{notification::Notification, response::HealthResponse};
#[derive(Clone, Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Resize(u16, u16),
    Health(HealthResponse),
    Pending(usize),
    Disconnected,
    Notification(Notification),
    Shutdown,
}
