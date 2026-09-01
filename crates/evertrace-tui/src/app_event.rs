use crossterm::event::KeyEvent;
use evertrace_protocol::{
    dto::{HumanGovernanceResponse, HumanRelationKind, HumanSurface},
    notification::Notification,
    response::{HealthResponse, RecoveryActionResponse},
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanReadLocator {
    List,
    Detail {
        expected_frontier: u64,
        stable_key: String,
        expected_revision_ref: Option<String>,
    },
    Related {
        relation: HumanRelationKind,
        source_stable_key: String,
        expected_source_revision_ref: String,
        expected_frontier: u64,
    },
}
#[derive(Clone, Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Resize(u16, u16),
    Health(HealthResponse),
    HumanRead {
        surface: HumanSurface,
        locator: HumanReadLocator,
        response: HumanGovernanceResponse,
    },
    HumanAction(HumanGovernanceResponse),
    Recovery(RecoveryActionResponse),
    Pending(usize),
    Disconnected,
    Notification(Notification),
    Shutdown,
}
