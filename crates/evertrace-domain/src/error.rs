use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    ScopeUnresolved,
    Conflict,
    NotFound,
    Untrusted,
    DegradedIndex,
    PendingImport,
    ResourceExhausted,
    ProtocolMismatch,
    MaintenanceMode,
    IdempotencyConflict,
    StoreCorrupt,
    Internal,
}

impl ErrorCode {
    pub const ALL: [Self; 13] = [
        Self::InvalidInput,
        Self::ScopeUnresolved,
        Self::Conflict,
        Self::NotFound,
        Self::Untrusted,
        Self::DegradedIndex,
        Self::PendingImport,
        Self::ResourceExhausted,
        Self::ProtocolMismatch,
        Self::MaintenanceMode,
        Self::IdempotencyConflict,
        Self::StoreCorrupt,
        Self::Internal,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::ScopeUnresolved => "scope_unresolved",
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
            Self::Untrusted => "untrusted",
            Self::DegradedIndex => "degraded_index",
            Self::PendingImport => "pending_import",
            Self::ResourceExhausted => "resource_exhausted",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::MaintenanceMode => "maintenance_mode",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::StoreCorrupt => "store_corrupt",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicError {
    code: ErrorCode,
}

impl PublicError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> ErrorCode {
        self.code
    }
}

impl fmt::Display for PublicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for PublicError {}
