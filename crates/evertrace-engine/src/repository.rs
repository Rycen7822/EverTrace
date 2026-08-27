//! Read-only bounded Git probe evidence and the
//! Repository/Worktree/Snapshot/Transition/Integration resolver.
//!
//! The probe ([`git_probe`]) is the only product code path that executes
//! `git`. It can only express the closed [`GitProbeOp`] allowlist, always runs
//! with `GIT_OPTIONAL_LOCKS=0`, no pager and a fixed `LC_ALL=C` locale, and
//! enforces [`ProbeLimits`] by killing the child process as soon as any bound
//! is exceeded. The resolver ([`resolver`]) and the integration resolver
//! ([`integration`]) allocate fresh UUIDv7 object and command IDs at
//! construction time; idempotent replay works because the caller re-submits
//! the already-constructed command and the writer deduplicates by command ID.

mod git_probe;
mod integration;
mod resolver;

pub use git_probe::{
    AdminPathProbe, GIT_PROBE_SCHEMA_VERSION, GitOid, GitProbeEvidence, GitProbeOp,
    HostTrustDecision, ProbeField, ProbeLimits, ProbeOmission, RepositoryProbeError,
    WorktreeAdminEntry, probe_is_ancestor, probe_patch_equivalence, probe_repository,
    remote_fingerprint,
};
pub use integration::{IntegrationEvidence, resolve_integration};
pub use resolver::{
    PathHint, RepositoryResolution, RepositoryResolveError, RepositoryResolveInput, ResolutionKind,
    correct_transition, resolve_repository,
};
