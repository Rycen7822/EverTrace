use serde::{Deserialize, Serialize};

use crate::dto::ClientKind;

pub(crate) const MAX_BUILD_ID_BYTES: usize = 128;

pub(crate) fn valid_build_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_BUILD_ID_BYTES
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Handshake {
    pub protocol_version: u32,
    pub client_kind: ClientKind,
    pub build_id: String,
    pub max_frame: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeAck {
    pub protocol_version: u32,
    pub build_id: String,
    pub max_frame: u32,
}
