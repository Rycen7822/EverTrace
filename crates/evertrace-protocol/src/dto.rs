use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Cli,
    Hook,
    Mcp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionContext {
    pub connection_id: String,
    pub client_kind: ClientKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthMode {
    Normal,
    Maintenance,
}
