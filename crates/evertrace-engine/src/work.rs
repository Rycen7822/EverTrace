//! S12 Task/Workstream command and derived-state facade.

pub mod attempt;
pub mod binding;
pub mod task;
pub mod workstream;

use evertrace_domain::ids::CommandId;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkCommandContext {
    pub command_id: CommandId,
    pub occurred_at_us: i64,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedTaskChange {
    Goal,
    Scope,
    Confidence,
    Lifecycle,
    Continuation,
    Split,
    Merge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedWorkstreamChange {
    StructuredRevision,
    MaterialGoalReplacement,
    WorktreeLineage,
    Status,
}

#[derive(Debug, Error)]
pub enum WorkIdentityError {
    #[error("work identity input is invalid")]
    InvalidInput,
    #[error("work identity scope is unresolved")]
    ScopeUnresolved,
    #[error("work identity state conflicts with current state")]
    Conflict,
    #[error(transparent)]
    Store(#[from] evertrace_store::StoreError),
}
