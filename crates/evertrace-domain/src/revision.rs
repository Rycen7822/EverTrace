use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::{Uuid, Variant};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevisionIdError {
    #[error("revision ID is not a canonical UUID")]
    InvalidUuid,
    #[error("revision ID is not UUIDv7")]
    WrongUuidVersion,
    #[error("revision ID does not use the RFC4122/RFC9562 variant")]
    WrongUuidVariant,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RevisionId(Uuid);

impl RevisionId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Result<Self, RevisionIdError> {
        if uuid.get_version_num() != 7 {
            return Err(RevisionIdError::WrongUuidVersion);
        }
        if uuid.get_variant() != Variant::RFC4122 {
            return Err(RevisionIdError::WrongUuidVariant);
        }
        Ok(Self(uuid))
    }

    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl Serialize for RevisionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RevisionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl FromStr for RevisionId {
    type Err = RevisionIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(value).map_err(|_| RevisionIdError::InvalidUuid)?;
        if uuid.hyphenated().to_string() != value {
            return Err(RevisionIdError::InvalidUuid);
        }
        Self::from_uuid(uuid)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AlgorithmRevision(u32);

impl AlgorithmRevision {
    pub const V1: Self = Self(1);

    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    pub const fn version(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionMetadata {
    created_at_us: i64,
    source_watermark: u64,
}

impl RevisionMetadata {
    pub const fn created_at_us(self) -> i64 {
        self.created_at_us
    }

    pub const fn source_watermark(self) -> u64 {
        self.source_watermark
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableRevision<T> {
    revision_id: RevisionId,
    parent: Option<RevisionId>,
    supersedes: Vec<RevisionId>,
    payload: T,
    metadata: RevisionMetadata,
}

impl<T> ImmutableRevision<T> {
    pub fn root(
        revision_id: RevisionId,
        payload: T,
        created_at_us: i64,
        source_watermark: u64,
    ) -> Self {
        Self {
            revision_id,
            parent: None,
            supersedes: Vec::new(),
            payload,
            metadata: RevisionMetadata {
                created_at_us,
                source_watermark,
            },
        }
    }

    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    pub const fn parent(&self) -> Option<RevisionId> {
        self.parent
    }

    pub fn supersedes(&self) -> &[RevisionId] {
        &self.supersedes
    }

    pub const fn payload(&self) -> &T {
        &self.payload
    }

    pub const fn metadata(&self) -> RevisionMetadata {
        self.metadata
    }

    pub fn successor(
        &self,
        revision_id: RevisionId,
        payload: T,
        created_at_us: i64,
        source_watermark: u64,
        additional_supersedes: impl IntoIterator<Item = RevisionId>,
    ) -> Self {
        let mut supersedes = vec![self.revision_id];
        for prior in additional_supersedes {
            if !supersedes.contains(&prior) {
                supersedes.push(prior);
            }
        }
        Self {
            revision_id,
            parent: Some(self.revision_id),
            supersedes,
            payload,
            metadata: RevisionMetadata {
                created_at_us,
                source_watermark,
            },
        }
    }
}
