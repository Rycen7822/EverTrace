//! Bounded production retrieval and separate request-local diagnostics.

mod diagnostic;
mod production;
mod resolution;
mod retrieval;

pub(crate) use resolution::SemanticSearchResolution;

pub use diagnostic::{DiagnosticRetrieval, DiagnosticSession};
pub use production::{DiagnosticFtsFailure, ProductionSearch, SearchError};

#[cfg(test)]
include!("tests.rs");
