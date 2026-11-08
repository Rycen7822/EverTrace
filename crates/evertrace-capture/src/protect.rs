use std::{borrow::Cow, fmt};

use evertrace_domain::canonical::{CanonicalValue, encode, hmac_sha256};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::key::DeviceKey;

pub const DETECTOR_REVISION: u32 = 2;
pub const REDACTION_REVISION: u32 = 2;
pub const REDACTION_TOKEN: &[u8] = b"[REDACTED]";

/// v1 is retained for immutable captured frames; mixed or unknown formats are not admitted.
pub fn supports_revisions(detector: u32, redaction: u32) -> bool {
    matches!((detector, redaction), (1, 1) | (2, 2))
}

const ASSIGNMENTS: &[(&[u8], SecretKind)] = &[
    (b"api_key", SecretKind::ApiKey),
    (b"apikey", SecretKind::ApiKey),
    (b"access_token", SecretKind::Token),
    (b"token", SecretKind::Token),
    (b"password", SecretKind::Credential),
    (b"credential", SecretKind::Credential),
    (b"secret_key", SecretKind::Credential),
];

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
    let candidates = resolve_overlaps(detect_candidates(input));
    let protected_bytes = if candidates.is_empty() {
        input.to_vec()
    } else {
        redact(input, &candidates)
    };
    let spans = candidates
        .into_iter()
        .map(|candidate| RedactionSpan {
            start: candidate.start as u64,
            end: candidate.end as u64,
            kind: candidate.kind,
        })
        .collect::<Vec<_>>();
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

/// Produces a fixed-domain device-keyed token for secret-safe recovery path
/// metadata. The raw path is never returned or persisted by this helper.
pub fn recovery_path_token(input: &[u8], key: &DeviceKey) -> Result<[u8; 32], ProtectError> {
    hmac_sha256(
        key.bytes(),
        "evertrace.recovery_path_token",
        1,
        &CanonicalValue::Bytes(input.to_vec()),
    )
    .map_err(|_| ProtectError::Digest)
}

/// Produces a fixed-domain device-keyed identity for transient recovery fence
/// comparison. It does not expose the captured bytes.
pub fn recovery_content_token(input: &[u8], key: &DeviceKey) -> Result<[u8; 32], ProtectError> {
    hmac_sha256(
        key.bytes(),
        "evertrace.recovery_content_token",
        1,
        &CanonicalValue::Bytes(input.to_vec()),
    )
    .map_err(|_| ProtectError::Digest)
}

/// Authenticates one canonical MCP call without exposing the device key or
/// creating a durable claim artifact.
pub fn mcp_call_auth_tag(input: &[u8], key: &DeviceKey) -> Result<[u8; 32], ProtectError> {
    hmac_sha256(
        key.bytes(),
        "evertrace.mcp_canonical_call",
        1,
        &CanonicalValue::Bytes(input.to_vec()),
    )
    .map_err(|_| ProtectError::Digest)
}

/// Verifies the canonical MCP call tag without a timing-sensitive comparison
/// at the daemon boundary.
pub fn verify_mcp_call_auth_tag(
    input: &[u8],
    key: &DeviceKey,
    provided: &[u8; 32],
) -> Result<bool, ProtectError> {
    let encoded = encode(
        "evertrace.mcp_canonical_call",
        1,
        &CanonicalValue::Bytes(input.to_vec()),
    )
    .map_err(|_| ProtectError::Digest)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.bytes()).expect("HMAC-SHA-256 accepts device keys");
    mac.update(&encoded);
    Ok(mac.verify_slice(provided).is_ok())
}

/// Authenticates the single canonical S16 bundle-application ticket claims.
/// This is intentionally not a general-purpose key or signing API.
pub fn recovery_ticket_auth_tag(
    claims: &CanonicalValue,
    key: &DeviceKey,
) -> Result<[u8; 32], ProtectError> {
    hmac_sha256(
        key.bytes(),
        "evertrace.recovery_application_ticket",
        1,
        claims,
    )
    .map_err(|_| ProtectError::Digest)
}

/// Verifies the canonical S16 ticket tag without a timing-sensitive array
/// comparison at the engine boundary.
pub fn verify_recovery_ticket_auth_tag(
    claims: &CanonicalValue,
    key: &DeviceKey,
    provided: &[u8; 32],
) -> Result<bool, ProtectError> {
    let encoded = encode("evertrace.recovery_application_ticket", 1, claims)
        .map_err(|_| ProtectError::Digest)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.bytes()).expect("HMAC-SHA-256 accepts device keys");
    mac.update(&encoded);
    Ok(mac.verify_slice(provided).is_ok())
}

#[derive(Clone, Copy)]
struct Candidate {
    start: usize,
    end: usize,
    kind: SecretKind,
    json_value: bool,
}

fn detect_candidates(input: &[u8]) -> Vec<Candidate> {
    detect_json_candidates(input).unwrap_or_else(|| detect_text_candidates(input))
}

fn detect_text_candidates(input: &[u8]) -> Vec<Candidate> {
    let mut output = Vec::new();
    detect_pem(input, &mut output);
    detect_bearer(input, &mut output);
    for &(name, kind) in ASSIGNMENTS {
        detect_assignment(input, name, kind, &mut output);
    }
    output
}

/// Validate without an object graph, then inspect one decoded string at a time.
/// Every candidate remains a byte range in the original input, not reserialized JSON.
fn detect_json_candidates(input: &[u8]) -> Option<Vec<Candidate>> {
    if !matches!(
        input
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{' | b'[' | b'"')
    ) {
        return None;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    serde::de::IgnoredAny::deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    let (mut cursor, mut output) = (0, Vec::new());
    while cursor < input.len() {
        if input[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let end = json_string_end(input, cursor)?;
        let raw = &input[cursor + 1..end - 1];
        let decoded = if raw.contains(&b'\\') {
            Cow::Owned(serde_json::from_slice::<String>(&input[cursor..end]).ok()?)
        } else {
            Cow::Borrowed(std::str::from_utf8(raw).ok()?)
        };
        let mut following = end;
        while input.get(following).is_some_and(u8::is_ascii_whitespace) {
            following += 1;
        }
        if input.get(following) == Some(&b':')
            && let Some(kind) = json_secret_kind(&decoded)
        {
            let start = following + 1;
            let start = start
                + input[start..]
                    .iter()
                    .take_while(|byte| byte.is_ascii_whitespace())
                    .count();
            let mut value = serde_json::Deserializer::from_slice(&input[start..])
                .into_iter::<serde::de::IgnoredAny>();
            value.next()?.ok()?;
            let value_end = start + value.byte_offset();
            if json_secret_value(kind, &input[start..value_end]) {
                output.push(Candidate {
                    start,
                    end: value_end,
                    kind,
                    json_value: true,
                });
                cursor = value_end;
                continue;
            }
        }
        let mut candidates = resolve_overlaps(detect_text_candidates(decoded.as_bytes()));
        map_json_offsets(raw, &mut candidates, cursor + 1)?;
        output.extend(candidates);
        cursor = end;
    }
    Some(output)
}

fn json_secret_kind(name: &str) -> Option<SecretKind> {
    if name.eq_ignore_ascii_case("authorization") {
        return Some(SecretKind::AuthorizationBearer);
    }
    ASSIGNMENTS
        .iter()
        .find_map(|(key, kind)| name.as_bytes().eq_ignore_ascii_case(key).then_some(*kind))
}

fn json_secret_value(kind: SecretKind, value: &[u8]) -> bool {
    let decoded = if value.first() == Some(&b'"') {
        let Ok(text) = serde_json::from_slice::<String>(value) else {
            return false;
        };
        Cow::Owned(text)
    } else {
        let Ok(text) = std::str::from_utf8(value) else {
            return false;
        };
        Cow::Borrowed(text)
    };
    let header = decoded.trim_ascii_start();
    decoded.len() >= 8
        && (kind != SecretKind::AuthorizationBearer
            || header
                .get(..6)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer"))
                && header
                    .as_bytes()
                    .get(6)
                    .is_some_and(u8::is_ascii_whitespace)
                && header[6..].trim_ascii().len() >= 8)
}

fn json_string_end(input: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start + 1;
    while let Some(byte) = input.get(cursor) {
        match byte {
            b'"' => return Some(cursor + 1),
            b'\\' => cursor += 2,
            _ => cursor += 1,
        }
    }
    None
}

/// Map sorted, disjoint decoded ranges in one pass, including UTF-16 surrogate pairs.
fn map_json_offsets(raw: &[u8], candidates: &mut [Candidate], offset: usize) -> Option<()> {
    let (mut cursor, mut decoded) = (0, 0);
    for candidate in candidates {
        for boundary in [&mut candidate.start, &mut candidate.end] {
            while decoded < *boundary {
                let byte = *raw.get(cursor)?;
                let (width, decoded_width) = if byte == b'\\' {
                    if raw.get(cursor + 1) == Some(&b'u') {
                        let digits = std::str::from_utf8(raw.get(cursor + 2..cursor + 6)?).ok()?;
                        let unit = u16::from_str_radix(digits, 16).ok()?;
                        if (0xd800..=0xdbff).contains(&unit) {
                            (12, 4)
                        } else {
                            (6, char::from_u32(u32::from(unit))?.len_utf8())
                        }
                    } else {
                        (2, 1)
                    }
                } else {
                    let width = byte.leading_ones().max(1) as usize;
                    (width, width)
                };
                cursor += width;
                decoded += decoded_width;
            }
            if decoded != *boundary || cursor > raw.len() {
                return None;
            }
            *boundary = offset + cursor;
        }
    }
    Some(())
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
        if input
            .get(value)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
            && start > 0
            && input[start - 1] == input[value]
        {
            value += 1;
        }
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
            if quote == Some(b'"') && input[end] == b'\\' && end + 1 < input.len() {
                end += 2;
            } else {
                end += 1;
            }
        }
        if end.saturating_sub(value) >= 8 {
            output.push(Candidate {
                start: value,
                end,
                kind,
                json_value: false,
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
        if input
            .get(position)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
            && start > 0
            && input[start - 1] == input[position]
        {
            position += 1;
        }
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
        let quote = input
            .get(position)
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
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
        while end < input.len()
            && !input[end].is_ascii_whitespace()
            && quote.is_none_or(|quote| input[end] != quote)
        {
            end += 1;
        }
        if end.saturating_sub(position) >= 8 {
            output.push(Candidate {
                start: position,
                end,
                kind: SecretKind::AuthorizationBearer,
                json_value: false,
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
                json_value: false,
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

fn redact(input: &[u8], candidates: &[Candidate]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut cursor = 0;
    for candidate in candidates {
        output.extend_from_slice(&input[cursor..candidate.start]);
        if candidate.json_value {
            output.push(b'"');
        }
        output.extend_from_slice(REDACTION_TOKEN);
        if candidate.json_value {
            output.push(b'"');
        }
        cursor = candidate.end;
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
