//! Bounded production retrieval and separate request-local diagnostics.

mod diagnostic;
pub(crate) mod execution;
mod production;
pub(crate) mod protection;
pub(crate) mod read_context;
mod resolution;
mod retrieval;

pub(crate) use production::{SourceSequenceScope, TemporalPosition, TemporalReadScope};
pub(crate) use resolution::SemanticSearchResolution;

pub use diagnostic::{DiagnosticRetrieval, DiagnosticSession};
pub use production::{DiagnosticFtsFailure, ProductionSearch, SearchError};

/// The whole request must name the relation and one stable operand. Other prose stays lexical.
pub(crate) fn explicit_atom_relation<'a>(
    input: &'a str,
    targets: &'a [String],
) -> Option<(&'a str, &'static str)> {
    use evertrace_domain::{ids::AtomId, revision::RevisionId};

    let request = input
        .trim()
        .strip_suffix('?')
        .unwrap_or(input.trim())
        .trim_end();
    let operand = if request.eq_ignore_ascii_case("what contradicts") {
        let [target] = targets else {
            return None;
        };
        target.as_str()
    } else {
        let (verb, operand) = request.rsplit_once(char::is_whitespace)?;
        if !verb.trim_end().eq_ignore_ascii_case("what contradicts")
            || targets.iter().any(|target| target != operand)
        {
            return None;
        }
        operand
    };
    (operand.parse::<AtomId>().is_ok() || operand.parse::<RevisionId>().is_ok())
        .then_some((operand, "atom_contradicts"))
}

#[cfg(test)]
include!("tests.rs");
