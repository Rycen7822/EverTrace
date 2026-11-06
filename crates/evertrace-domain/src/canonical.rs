use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

const FORMAT_MAGIC: &[u8; 4] = b"ETC1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i128),
    String(String),
    Bytes(Vec<u8>),
    Sequence(Vec<Self>),
    Map(Vec<(String, Self)>),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CanonicalError {
    #[error("canonical schema tag must not be empty")]
    EmptySchemaTag,
    #[error("canonical map contains a duplicate key")]
    DuplicateMapKey,
    #[error("canonical value length exceeds the supported encoding")]
    LengthOverflow,
    #[error("canonical byte stream is invalid, incomplete or excessive")]
    InvalidByteStream,
}

pub fn encode(
    schema_tag: &str,
    schema_version: u32,
    value: &CanonicalValue,
) -> Result<Vec<u8>, CanonicalError> {
    let mut output = encode_header(schema_tag, schema_version)?;
    encode_value(value, &mut output)?;
    Ok(output)
}

/// Hashes one declared root-map byte field without retaining its contents.
/// Ordinary encode and this calculator share framing, sorting and metadata encoding.
/// The selected entry must be Bytes(empty), replaced by exactly `length` streamed bytes.
pub(crate) struct CanonicalBytesHasher {
    checksum: Sha256,
    suffix: Vec<u8>,
    remaining: usize,
}

impl CanonicalBytesHasher {
    pub(crate) fn new(
        schema_tag: &str,
        schema_version: u32,
        entries: &[(String, CanonicalValue)],
        field: &str,
        length: usize,
    ) -> Result<Self, CanonicalError> {
        let mut prefix = encode_header(schema_tag, schema_version)?;
        let split = encode_map(entries, &mut prefix, Some((field, length)))?
            .ok_or(CanonicalError::InvalidByteStream)?;
        let suffix = prefix.split_off(split);
        let mut checksum = Sha256::new();
        checksum.update(&prefix);
        Ok(Self {
            checksum,
            suffix,
            remaining: length,
        })
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<(), CanonicalError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or(CanonicalError::InvalidByteStream)?;
        self.checksum.update(bytes);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<[u8; 32], CanonicalError> {
        if self.remaining != 0 {
            return Err(CanonicalError::InvalidByteStream);
        }
        self.checksum.update(&self.suffix);
        Ok(self.checksum.finalize().into())
    }
}

pub fn sha256(
    schema_tag: &str,
    schema_version: u32,
    value: &CanonicalValue,
) -> Result<[u8; 32], CanonicalError> {
    let encoded = encode(schema_tag, schema_version, value)?;
    Ok(Sha256::digest(encoded).into())
}

pub fn hmac_sha256(
    key: &[u8],
    schema_tag: &str,
    schema_version: u32,
    value: &CanonicalValue,
) -> Result<[u8; 32], CanonicalError> {
    let encoded = encode(schema_tag, schema_version, value)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts caller-supplied keys of any length");
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}

fn encode_value(value: &CanonicalValue, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        CanonicalValue::Null => output.push(b'N'),
        CanonicalValue::Bool(boolean) => {
            output.push(b'B');
            output.push(u8::from(*boolean));
        }
        CanonicalValue::Integer(integer) => {
            output.push(b'I');
            output.extend_from_slice(&integer.to_be_bytes());
        }
        CanonicalValue::String(string) => {
            output.push(b'S');
            push_len(output, string.len())?;
            output.extend_from_slice(string.as_bytes());
        }
        CanonicalValue::Bytes(bytes) => {
            encode_bytes_header(output, bytes.len())?;
            output.extend_from_slice(bytes);
        }
        CanonicalValue::Sequence(items) => {
            output.push(b'Q');
            push_len(output, items.len())?;
            for item in items {
                encode_value(item, output)?;
            }
        }
        CanonicalValue::Map(entries) => {
            encode_map(entries, output, None)?;
        }
    }
    Ok(())
}

fn encode_header(schema_tag: &str, schema_version: u32) -> Result<Vec<u8>, CanonicalError> {
    if schema_tag.is_empty() {
        return Err(CanonicalError::EmptySchemaTag);
    }
    let mut output = Vec::new();
    output.extend_from_slice(FORMAT_MAGIC);
    push_len(&mut output, schema_tag.len())?;
    output.extend_from_slice(schema_tag.as_bytes());
    output.extend_from_slice(&schema_version.to_be_bytes());
    Ok(output)
}

fn encode_bytes_header(output: &mut Vec<u8>, length: usize) -> Result<(), CanonicalError> {
    output.push(b'Y');
    push_len(output, length)
}

fn encode_map(
    entries: &[(String, CanonicalValue)],
    output: &mut Vec<u8>,
    streamed: Option<(&str, usize)>,
) -> Result<Option<usize>, CanonicalError> {
    output.push(b'M');
    push_len(output, entries.len())?;
    let mut sorted = entries.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    for pair in sorted.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(CanonicalError::DuplicateMapKey);
        }
    }
    let mut split = None;
    for (key, value) in sorted {
        push_len(output, key.len())?;
        output.extend_from_slice(key.as_bytes());
        if let Some((field, length)) = streamed
            && key == field
        {
            if !matches!(value, CanonicalValue::Bytes(bytes) if bytes.is_empty()) {
                return Err(CanonicalError::InvalidByteStream);
            }
            encode_bytes_header(output, length)?;
            split = Some(output.len());
        } else {
            encode_value(value, output)?;
        }
    }
    Ok(split)
}

fn push_len(output: &mut Vec<u8>, length: usize) -> Result<(), CanonicalError> {
    let length = u64::try_from(length).map_err(|_| CanonicalError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}
