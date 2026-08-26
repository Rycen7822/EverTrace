use std::fmt;

use evertrace_domain::canonical::{CanonicalValue, hmac_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::key::DeviceKey;

pub const DETECTOR_REVISION: u32 = 1;
pub const REDACTION_REVISION: u32 = 1;
const REDACTION_TOKEN: &[u8] = b"[REDACTED]";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveMode {
    Exact,
    Redacted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
    Token,
    Credential,
    AuthorizationBearer,
    PemPrivateKey,
}

impl SecretKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Token => "token",
            Self::Credential => "credential",
            Self::AuthorizationBearer => "authorization_bearer",
            Self::PemPrivateKey => "pem_private_key",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::PemPrivateKey => 3,
            Self::AuthorizationBearer => 2,
            Self::ApiKey | Self::Token | Self::Credential => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionSpan {
    start: u64,
    end: u64,
    kind: SecretKind,
}

impl RedactionSpan {
    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn end(&self) -> u64 {
        self.end
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedPayload {
    protected_bytes: Vec<u8>,
    raw_length: u64,
    spans: Vec<RedactionSpan>,
    detector_revision: u32,
    redaction_revision: u32,
    key_generation: u64,
    protected_secret_digest: Option<[u8; 32]>,
}

impl fmt::Debug for ProtectedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedPayload")
            .field("archive_mode", &self.archive_mode())
            .field("raw_length", &self.raw_length)
            .field("span_count", &self.spans.len())
            .field("detector_revision", &self.detector_revision)
            .field("redaction_revision", &self.redaction_revision)
            .field("key_generation", &self.key_generation)
            .field(
                "has_protected_secret_digest",
                &self.protected_secret_digest.is_some(),
            )
            .finish()
    }
}

impl ProtectedPayload {
    pub fn archive_mode(&self) -> ArchiveMode {
        if self.spans.is_empty() {
            ArchiveMode::Exact
        } else {
            ArchiveMode::Redacted
        }
    }

    pub fn protected_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }

    pub const fn raw_length(&self) -> u64 {
        self.raw_length
    }

    pub fn spans(&self) -> &[RedactionSpan] {
        &self.spans
    }

    pub const fn detector_revision(&self) -> u32 {
        self.detector_revision
    }

    pub const fn redaction_revision(&self) -> u32 {
        self.redaction_revision
    }

    pub const fn key_generation(&self) -> u64 {
        self.key_generation
    }

    pub const fn protected_secret_digest(&self) -> Option<[u8; 32]> {
        self.protected_secret_digest
    }

    pub(crate) const fn protection_version(&self) -> u16 {
        1
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtectError {
    #[error("protected payload is too large")]
    LengthOverflow,
    #[error("protected secret digest could not be computed")]
    Digest,
}

pub fn protect(input: &[u8], key: &DeviceKey) -> Result<ProtectedPayload, ProtectError> {
    let raw_length = u64::try_from(input.len()).map_err(|_| ProtectError::LengthOverflow)?;
    let spans = resolve_overlaps(detect_candidates(input))
        .into_iter()
        .map(|candidate| RedactionSpan {
            start: candidate.start as u64,
            end: candidate.end as u64,
            kind: candidate.kind,
        })
        .collect::<Vec<_>>();
    let protected_bytes = if spans.is_empty() {
        input.to_vec()
    } else {
        redact(input, &spans)
    };
    let protected_secret_digest = if spans.is_empty() {
        None
    } else {
        let digest_spans = spans
            .iter()
            .map(|span| {
                let start = span.start as usize;
                let end = span.end as usize;
                CanonicalValue::Map(vec![
                    (
                        "kind".into(),
                        CanonicalValue::String(span.kind.as_str().into()),
                    ),
                    (
                        "start".into(),
                        CanonicalValue::Integer(i128::from(span.start)),
                    ),
                    ("end".into(), CanonicalValue::Integer(i128::from(span.end))),
                    (
                        "bytes".into(),
                        CanonicalValue::Bytes(input[start..end].to_vec()),
                    ),
                ])
            })
            .collect();
        let value = CanonicalValue::Map(vec![
            (
                "raw_length".into(),
                CanonicalValue::Integer(i128::from(raw_length)),
            ),
            ("spans".into(), CanonicalValue::Sequence(digest_spans)),
        ]);
        Some(
            hmac_sha256(
                key.bytes(),
                "evertrace.protected_secret",
                REDACTION_REVISION,
                &value,
            )
            .map_err(|_| ProtectError::Digest)?,
        )
    };
    Ok(ProtectedPayload {
        protected_bytes,
        raw_length,
        spans,
        detector_revision: DETECTOR_REVISION,
        redaction_revision: REDACTION_REVISION,
        key_generation: key.generation(),
        protected_secret_digest,
    })
}

#[derive(Clone, Copy)]
struct Candidate {
    start: usize,
    end: usize,
    kind: SecretKind,
}

fn detect_candidates(input: &[u8]) -> Vec<Candidate> {
    let mut output = Vec::new();
    detect_pem(input, &mut output);
    detect_bearer(input, &mut output);
    for (name, kind) in [
        (b"api_key".as_slice(), SecretKind::ApiKey),
        (b"apikey".as_slice(), SecretKind::ApiKey),
        (b"access_token".as_slice(), SecretKind::Token),
        (b"token".as_slice(), SecretKind::Token),
        (b"password".as_slice(), SecretKind::Credential),
        (b"credential".as_slice(), SecretKind::Credential),
        (b"secret_key".as_slice(), SecretKind::Credential),
    ] {
        detect_assignment(input, name, kind, &mut output);
    }
    output
}

fn detect_assignment(input: &[u8], name: &[u8], kind: SecretKind, output: &mut Vec<Candidate>) {
    let mut cursor = 0;
    while let Some(relative) = find_ascii_case_insensitive(&input[cursor..], name) {
        let start = cursor + relative;
        cursor = start + name.len();
        if (start > 0 && is_name_byte(input[start - 1]))
            || (cursor < input.len() && is_name_byte(input[cursor]))
        {
            continue;
        }
        let mut value = cursor;
        while value < input.len() && matches!(input[value], b' ' | b'\t') {
            value += 1;
        }
        if value >= input.len() || !matches!(input[value], b'=' | b':') {
            continue;
        }
        value += 1;
        while value < input.len() && matches!(input[value], b' ' | b'\t') {
            value += 1;
        }
        let quote = input
            .get(value)
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
            value += 1;
        }
        let mut end = value;
        while end < input.len()
            && if let Some(quote) = quote {
                input[end] != quote && !matches!(input[end], b'\r' | b'\n')
            } else {
                !matches!(input[end], b' ' | b'\t' | b'\r' | b'\n' | b',' | b';')
            }
        {
            end += 1;
        }
        if end.saturating_sub(value) >= 8 {
            output.push(Candidate {
                start: value,
                end,
                kind,
            });
        }
    }
}

fn detect_bearer(input: &[u8], output: &mut Vec<Candidate>) {
    const PREFIX: &[u8] = b"authorization";
    let mut cursor = 0;
    while let Some(relative) = find_ascii_case_insensitive(&input[cursor..], PREFIX) {
        let start = cursor + relative;
        cursor = start + PREFIX.len();
        if start > 0 && is_name_byte(input[start - 1]) {
            continue;
        }
        let mut position = cursor;
        while position < input.len() && matches!(input[position], b' ' | b'\t') {
            position += 1;
        }
        if input.get(position) != Some(&b':') {
            continue;
        }
        position += 1;
        while position < input.len() && matches!(input[position], b' ' | b'\t') {
            position += 1;
        }
        let bearer = b"bearer";
        if position + bearer.len() > input.len()
            || !input[position..position + bearer.len()].eq_ignore_ascii_case(bearer)
        {
            continue;
        }
        position += bearer.len();
        if !input.get(position).is_some_and(u8::is_ascii_whitespace) {
            continue;
        }
        while position < input.len() && matches!(input[position], b' ' | b'\t') {
            position += 1;
        }
        let mut end = position;
        while end < input.len() && !input[end].is_ascii_whitespace() {
            end += 1;
        }
        if end.saturating_sub(position) >= 8 {
            output.push(Candidate {
                start: position,
                end,
                kind: SecretKind::AuthorizationBearer,
            });
        }
    }
}

fn detect_pem(input: &[u8], output: &mut Vec<Candidate>) {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const PRIVATE: &[u8] = b"PRIVATE KEY-----";
    const END_PREFIX: &[u8] = b"-----END ";
    let mut cursor = 0;
    while let Some(relative) = find_bytes(&input[cursor..], BEGIN) {
        let start = cursor + relative;
        cursor = start + BEGIN.len();
        let Some(kind_end_relative) = find_bytes(&input[cursor..], PRIVATE) else {
            break;
        };
        let label_end = cursor + kind_end_relative + PRIVATE.len();
        let label = &input[cursor..label_end - 5];
        let mut end_marker = Vec::with_capacity(END_PREFIX.len() + label.len() + 5);
        end_marker.extend_from_slice(END_PREFIX);
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(b"-----");
        if let Some(end_relative) = find_bytes(&input[label_end..], &end_marker) {
            let end = label_end + end_relative + end_marker.len();
            output.push(Candidate {
                start,
                end,
                kind: SecretKind::PemPrivateKey,
            });
            cursor = end;
        }
    }
}

fn resolve_overlaps(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|left, right| {
        right
            .kind
            .priority()
            .cmp(&left.kind.priority())
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
            .then_with(|| left.start.cmp(&right.start))
    });
    let mut selected = Vec::<Candidate>::new();
    for candidate in candidates {
        if selected
            .iter()
            .all(|current| candidate.end <= current.start || candidate.start >= current.end)
        {
            selected.push(candidate);
        }
    }
    selected.sort_by_key(|candidate| candidate.start);
    selected
}

fn redact(input: &[u8], spans: &[RedactionSpan]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut cursor = 0;
    for span in spans {
        let start = span.start as usize;
        let end = span.end as usize;
        output.extend_from_slice(&input[cursor..start]);
        output.extend_from_slice(REDACTION_TOKEN);
        cursor = end;
    }
    output.extend_from_slice(&input[cursor..]);
    output
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
