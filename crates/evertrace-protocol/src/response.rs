use evertrace_domain::ids::RequestId;
use serde::{Deserialize, Serialize};

use crate::dto::HealthMode;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub request_id: RequestId,
    pub response: Response,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub protocol_version: u32,
    pub mode: HealthMode,
    pub config_version: u32,
    pub effective_config_hash: String,
    pub algorithm_revision: u32,
}
