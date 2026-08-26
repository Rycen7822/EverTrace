use serde::{Deserialize, Serialize};

use crate::{
    command::CommandEnvelope,
    error::WireError,
    handshake::{Handshake, HandshakeAck},
    notification::NotificationEnvelope,
    response::ResponseEnvelope,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientEnvelope {
    Handshake(Handshake),
    Command(CommandEnvelope),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServerEnvelope {
    HandshakeAck(HandshakeAck),
    Response(ResponseEnvelope),
    Notification(NotificationEnvelope),
    Error(WireError),
}
