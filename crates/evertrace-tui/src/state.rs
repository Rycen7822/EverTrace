use evertrace_protocol::response::HealthResponse;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Inbox,
    Explorer,
    System,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected,
    ServerStopping,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellSnapshot {
    pub health: Option<HealthResponse>,
    pub connection: ConnectionState,
    pub pending: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppState {
    pub route: Route,
    pub shell: ShellSnapshot,
    pub quit: bool,
}
impl Default for AppState {
    fn default() -> Self {
        Self {
            route: Route::Inbox,
            shell: ShellSnapshot {
                health: None,
                connection: ConnectionState::Connecting,
                pending: 0,
            },
            quit: false,
        }
    }
}
