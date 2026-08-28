//! Bounded retrieval with a production-only A path and request-local diagnostics.

mod diagnostic;
mod production;

pub use diagnostic::{DiagnosticRetrieval, DiagnosticSession};
pub use production::{DiagnosticFtsFailure, ProductionSearch, SearchError};

#[cfg(test)]
include!("tests.rs");
