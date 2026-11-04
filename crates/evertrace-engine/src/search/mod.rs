//! Bounded production retrieval and separate request-local diagnostics.

mod diagnostic;
pub(crate) mod execution;
mod production;
pub(crate) mod protection;
mod resolution;
mod retrieval;

pub(crate) use production::{SourceSequenceScope, TemporalPosition, TemporalReadScope};
pub(crate) use resolution::SemanticSearchResolution;

pub use diagnostic::{DiagnosticRetrieval, DiagnosticSession};
pub use production::{DiagnosticFtsFailure, ProductionSearch, SearchError};

#[cfg(test)]
include!("tests.rs");
