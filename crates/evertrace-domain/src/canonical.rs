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
}

pub fn encode(
    schema_tag: &str,
    schema_version: u32,
    value: &CanonicalValue,
) -> Result<Vec<u8>, CanonicalError> {
    if schema_tag.is_empty() {
        return Err(CanonicalError::EmptySchemaTag);
    }
    let mut output = Vec::new();
    output.extend_from_slice(FORMAT_MAGIC);
    push_len(&mut output, schema_tag.len())?;
    output.extend_from_slice(schema_tag.as_bytes());
    output.extend_from_slice(&schema_version.to_be_bytes());
    encode_value(value, &mut output)?;
    Ok(output)
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
            output.push(b'Y');
            push_len(output, bytes.len())?;
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
            output.push(b'M');
            push_len(output, entries.len())?;
            let mut sorted = entries.iter().collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            for pair in sorted.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(CanonicalError::DuplicateMapKey);
                }
            }
            for (key, entry_value) in sorted {
                push_len(output, key.len())?;
                output.extend_from_slice(key.as_bytes());
                encode_value(entry_value, output)?;
            }
        }
    }
    Ok(())
}

fn push_len(output: &mut Vec<u8>, length: usize) -> Result<(), CanonicalError> {
    let length = u64::try_from(length).map_err(|_| CanonicalError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}
