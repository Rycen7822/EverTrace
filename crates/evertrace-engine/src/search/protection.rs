//! Request-local query protection; Capture remains the only secret detector.
use std::{collections::BTreeSet, ops::Range};

use evertrace_capture::{DeviceKey, RedactionSpan, protect};
use evertrace_domain::query::{
    FacetParseStatus, MAX_QUERY_BYTES, ProtectedFacet, ProtectedFacetKind, QueryError,
    QueryFacetSet,
};

pub(crate) struct PreparedQuery {
    pub text: String,
    pub facets: QueryFacetSet,
    pub protected_facets: BTreeSet<ProtectedFacet>,
}

pub(crate) fn prepare(
    raw: &str,
    facets: &QueryFacetSet,
    key: &DeviceKey,
) -> Result<PreparedQuery, QueryError> {
    if raw.is_empty() || raw.len() > MAX_QUERY_BYTES {
        return Err(QueryError::Invalid);
    }
    facets.validate()?;
    let payload = protect(raw.as_bytes(), key).map_err(|_| QueryError::Invalid)?;
    let ranges = known_secret_ranges(raw.as_bytes(), payload.spans());
    let mut bytes = Vec::new();
    let mut offset = 0;
    for range in &ranges {
        bytes.extend_from_slice(&raw.as_bytes()[offset..range.start]);
        bytes.extend_from_slice(evertrace_capture::protect::REDACTION_TOKEN);
        offset = range.end;
    }
    bytes.extend_from_slice(&raw.as_bytes()[offset..]);
    let text = String::from_utf8(bytes).map_err(|_| QueryError::Invalid)?;
    if text.len() > MAX_QUERY_BYTES {
        return Err(QueryError::Invalid);
    }
    let mut facets = facets.clone();
    let mut protected_facets = BTreeSet::new();
    for (kind, values) in [
        (
            ProtectedFacetKind::ExactIdentifier,
            &mut facets.exact_identifiers,
        ),
        (
            ProtectedFacetKind::ConditionLiteral,
            &mut facets.condition_literals,
        ),
        (
            ProtectedFacetKind::Exclusion,
            &mut facets.explicit_exclusions,
        ),
        (
            ProtectedFacetKind::Relation,
            &mut facets.relation_requirements,
        ),
    ] {
        let mut retained = Vec::with_capacity(values.len());
        for (position, value) in values.drain(..).enumerate() {
            let own = protect(value.as_bytes(), key).map_err(|_| QueryError::Invalid)?;
            if touches(raw.as_bytes(), value.as_bytes(), &ranges)
                || payload.spans().iter().any(|span| {
                    let secret = &raw.as_bytes()[span.start() as usize..span.end() as usize];
                    token_starts(value.as_bytes(), secret).next().is_some()
                })
                || own.protected_bytes() != value.as_bytes()
            {
                protected_facets.insert(ProtectedFacet {
                    kind,
                    position: position as u16,
                });
            } else {
                retained.push(value);
            }
        }
        *values = retained;
    }
    if !protected_facets.is_empty() && facets.parse_status == FacetParseStatus::Complete {
        facets.parse_status = FacetParseStatus::Partial;
    }
    Ok(PreparedQuery {
        text,
        facets,
        protected_facets,
    })
}

fn known_secret_ranges(raw: &[u8], spans: &[RedactionSpan]) -> Vec<Range<usize>> {
    let values = spans
        .iter()
        .map(|span| &raw[span.start() as usize..span.end() as usize])
        .collect::<BTreeSet<_>>();
    let mut ranges = spans
        .iter()
        .map(|span| span.start() as usize..span.end() as usize)
        .collect::<Vec<_>>();
    for value in values {
        ranges.extend(token_starts(raw, value).map(|start| start..start + value.len()));
    }
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

// Only whole lexical tokens inherit a detected value's protection. A credential
// named `candidate` must not erase the public identifier `schema-candidate`.
fn token_starts<'a>(text: &'a [u8], value: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let word =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') || byte >= 128;
    text.windows(value.len())
        .enumerate()
        .filter_map(move |(start, bytes)| {
            let end = start + value.len();
            (bytes == value
                && (start == 0 || !word(text[start - 1]))
                && (end == text.len() || !word(text[end])))
            .then_some(start)
        })
}

fn touches(raw: &[u8], value: &[u8], ranges: &[Range<usize>]) -> bool {
    // Byte windows include overlapping occurrences and never cut/rewrite a
    // UTF-8 token. Ambiguous safe/secret occurrences stay unknown too.
    raw.windows(value.len()).enumerate().any(|(start, bytes)| {
        bytes == value
            && ranges
                .iter()
                .any(|range| start < range.end && start + value.len() > range.start)
    })
}
