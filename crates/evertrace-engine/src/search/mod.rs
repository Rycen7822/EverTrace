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

/// Exact phrase with one existing `refs` operand, never inferred from general prose.
pub(crate) fn explicit_operation_binding(
    input: &str,
    targets: &[String],
) -> Option<evertrace_domain::ids::OperationId> {
    let [target] = targets else {
        return None;
    };
    if !input
        .trim()
        .trim_end_matches('?')
        .trim_end()
        .eq_ignore_ascii_case("trace operation binding")
    {
        return None;
    }
    target.parse().ok()
}

/// Exact phrase and one revision; a UUID in prose does not open a Global relation.
pub(crate) fn explicit_global_support(
    input: &str,
    targets: &[String],
) -> Option<evertrace_domain::revision::RevisionId> {
    let [target] = targets else { return None };
    let request = input.trim().trim_end_matches('?').trim_end();
    request
        .eq_ignore_ascii_case("trace global support")
        .then(|| target.parse().ok())
        .flatten()
}

fn source_target(reference: &str) -> bool {
    use evertrace_domain::{evidence::EvidenceSurface, ids::SourceObservationId};
    reference.parse::<SourceObservationId>().is_ok()
        || EvidenceSurface::parse_candidate_ref(reference).is_some()
}

/// Closed selectors over nominated source operands; no inference from question prose.
pub(crate) fn explicit_source_shape(
    input: &str,
    targets: &[String],
) -> Option<(
    evertrace_domain::query::AnswerShape,
    evertrace_domain::query::TemporalOrdering,
)> {
    use evertrace_domain::query::{AnswerShape, TemporalOrdering};

    if targets.is_empty() || !targets.iter().all(|reference| source_target(reference)) {
        return None;
    }
    let text = input.trim().trim_end_matches('?').trim_end();
    let (form, clause) = text.split_once(' ')?;
    let (by, domain) = clause.split_once(' ')?;
    if !by.eq_ignore_ascii_case("by") {
        return None;
    }
    let shape = if form.eq_ignore_ascii_case("compare") && targets.len() == 2 {
        AnswerShape::TemporalComparison
    } else if form.eq_ignore_ascii_case("timeline") {
        AnswerShape::Timeline
    } else if form.eq_ignore_ascii_case("latest") {
        AnswerShape::Latest
    } else {
        return None;
    };
    let order = if domain.eq_ignore_ascii_case("source sequence") {
        TemporalOrdering::SourceSequence
    } else if domain.eq_ignore_ascii_case("event time") {
        TemporalOrdering::EventTime
    } else {
        return None;
    };
    Some((shape, order))
}

pub(crate) fn explicit_count_unit(
    input: &str,
    targets: &[String],
) -> Option<evertrace_domain::query::CountUnit> {
    use evertrace_domain::{ids::AtomId, query::CountUnit, revision::RevisionId};

    if targets.is_empty() {
        return None;
    }
    let text = input.trim().trim_end_matches('?').trim_end();
    if text.eq_ignore_ascii_case("count referenced source observations")
        && targets.iter().all(|id| source_target(id))
    {
        return Some(CountUnit::SourceObservation);
    }
    if text.eq_ignore_ascii_case("count referenced atom revisions")
        && targets
            .iter()
            .all(|id| id.parse::<AtomId>().is_ok() || id.parse::<RevisionId>().is_ok())
    {
        return Some(CountUnit::ObjectRevision);
    }
    None
}

const EXACT_SLOT_SEPARATOR: &str = "; exact ";

pub(crate) fn entity_list_topic(input: &str) -> Option<&str> {
    let topic = input.trim_start().strip_prefix("list entities:")?.trim();
    (!topic.is_empty()).then_some(topic)
}

/// Only explicitly delimited identifiers become required slots of an anchored search.
pub(crate) fn explicit_exact_slots(input: &str, targets: &[String]) -> Option<Vec<String>> {
    let mut fields = input.split(EXACT_SLOT_SEPARATOR);
    if targets.is_empty() || fields.next()?.trim().is_empty() {
        return None;
    }
    let mut identifiers = Vec::new();
    for field in fields {
        let identifier = field.trim().strip_prefix('`')?.strip_suffix('`')?;
        if !(1..=128).contains(&identifier.len())
            || !identifier.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
            || !identifier.bytes().any(|byte| byte.is_ascii_alphanumeric())
        {
            return None;
        }
        if !identifiers.iter().any(|old| old == identifier) {
            identifiers.push(identifier.to_owned());
        }
        if identifiers.len() > 3 {
            return None;
        }
    }
    (!identifiers.is_empty()).then_some(identifiers)
}

#[cfg(test)]
include!("tests.rs");
