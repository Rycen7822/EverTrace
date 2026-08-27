use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::{Uuid, Variant};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdParseError {
    #[error("object ID is missing its family separator")]
    MissingSeparator,
    #[error("object ID has an empty payload")]
    EmptyPayload,
    #[error("object ID has the wrong family")]
    WrongFamily,
    #[error("object ID has an unknown family")]
    UnknownFamily,
    #[error("object ID UUID payload is invalid")]
    InvalidUuid,
    #[error("object ID UUID payload is not version 7")]
    WrongUuidVersion,
    #[error("object ID UUID payload does not use the RFC4122/RFC9562 variant")]
    WrongUuidVariant,
    #[error("object ID UUID payload is not canonical lowercase hyphenated form")]
    NonCanonicalUuid,
    #[error("object ID digest payload is not lowercase 64-hex")]
    InvalidDigest,
    #[error("projection IDs cannot be organize targets")]
    ProjectionNotOrganizable,
}

fn split_family<'a>(value: &'a str, expected: &str) -> Result<&'a str, IdParseError> {
    let (family, payload) = value
        .split_once(':')
        .ok_or(IdParseError::MissingSeparator)?;
    if family != expected {
        return Err(IdParseError::WrongFamily);
    }
    if payload.is_empty() {
        return Err(IdParseError::EmptyPayload);
    }
    Ok(payload)
}

fn parse_uuid_payload(payload: &str) -> Result<Uuid, IdParseError> {
    let uuid = Uuid::parse_str(payload).map_err(|_| IdParseError::InvalidUuid)?;
    validate_uuid(uuid)?;
    if uuid.hyphenated().to_string() != payload {
        return Err(IdParseError::NonCanonicalUuid);
    }
    Ok(uuid)
}

fn validate_uuid(uuid: Uuid) -> Result<(), IdParseError> {
    if uuid.get_version_num() != 7 {
        return Err(IdParseError::WrongUuidVersion);
    }
    if uuid.get_variant() != Variant::RFC4122 {
        return Err(IdParseError::WrongUuidVariant);
    }
    Ok(())
}

fn parse_digest_payload(payload: &str) -> Result<[u8; 32], IdParseError> {
    if payload.len() != 64
        || !payload
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(IdParseError::InvalidDigest);
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in payload.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| IdParseError::InvalidDigest)?;
        digest[index] = u8::from_str_radix(text, 16).map_err(|_| IdParseError::InvalidDigest)?;
    }
    Ok(digest)
}

fn write_digest(
    formatter: &mut fmt::Formatter<'_>,
    prefix: &str,
    digest: &[u8; 32],
) -> fmt::Result {
    write!(formatter, "{prefix}:")?;
    for byte in digest {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! uuid_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            pub const FAMILY: &'static str = $prefix;

            pub fn from_uuid(uuid: Uuid) -> Result<Self, IdParseError> {
                validate_uuid(uuid)?;
                Ok(Self(uuid))
            }

            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let payload = split_family(value, $prefix)?;
                Ok(Self(parse_uuid_payload(payload)?))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}:{}", $prefix, self.0.hyphenated())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! internal_uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_uuid(uuid: Uuid) -> Result<Self, IdParseError> {
                validate_uuid(uuid)?;
                Ok(Self(uuid))
            }

            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Ok(Self(parse_uuid_payload(value)?))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0.hyphenated())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! digest_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const FAMILY: &'static str = $prefix;

            pub const fn from_digest(digest: [u8; 32]) -> Self {
                Self(digest)
            }

            pub const fn as_digest(self) -> [u8; 32] {
                self.0
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let payload = split_family(value, $prefix)?;
                Ok(Self(parse_digest_payload(payload)?))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_digest(formatter, $prefix, &self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

digest_id!(SourceObservationId, "obs");
digest_id!(HostOccurrenceId, "occ");
digest_id!(SourceReceiptId, "src");
uuid_id!(CaptureReceiptId, "cap");
uuid_id!(CaptureOutageIntervalId, "outage");
uuid_id!(OperationId, "op");
uuid_id!(ScopeEffectId, "se");
uuid_id!(WorkBindingRevisionId, "wb");
uuid_id!(RepositoryId, "repo");
uuid_id!(WorktreeId, "wt");
uuid_id!(WorktreeSnapshotId, "wts");
uuid_id!(WorktreeTransitionId, "wtt");
uuid_id!(IntegrationEventId, "int");
uuid_id!(RecoveryCaptureRequestId, "recreq");
uuid_id!(RecoveryBundleId, "rec");
uuid_id!(RecoveryApplicationId, "recapp");
uuid_id!(TaskId, "task");
uuid_id!(WorkstreamId, "ws");
uuid_id!(ExecutionLaneId, "lane");
uuid_id!(WorkEpisodeId, "ep");
uuid_id!(AttemptId, "att");
uuid_id!(CompetingAttemptGroupId, "cmp");
uuid_id!(ExperimentRunId, "run");
uuid_id!(AtomId, "atom");
uuid_id!(ProcedureId, "proc");
uuid_id!(RevisionProposalId, "proposal");
uuid_id!(CoreMembershipId, "coremem");
digest_id!(WikiProjectionId, "wiki");
digest_id!(CoreProjectionId, "core");
uuid_id!(WorkArtifactId, "art");
uuid_id!(DuplicateGroupId, "dup");
digest_id!(CasId, "cas");
internal_uuid_id!(CommandId);
internal_uuid_id!(JobId);
internal_uuid_id!(RequestId);

impl OperationId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl CaptureReceiptId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl CaptureOutageIntervalId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl ExecutionLaneId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl ScopeEffectId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl DuplicateGroupId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl RepositoryId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl WorktreeId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl WorktreeSnapshotId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl WorktreeTransitionId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl IntegrationEventId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl TaskId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

impl WorkstreamId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnyPublicId {
    SourceObservation(SourceObservationId),
    HostOccurrence(HostOccurrenceId),
    SourceReceipt(SourceReceiptId),
    CaptureReceipt(CaptureReceiptId),
    CaptureOutageInterval(CaptureOutageIntervalId),
    Operation(OperationId),
    ScopeEffect(ScopeEffectId),
    WorkBindingRevision(WorkBindingRevisionId),
    Repository(RepositoryId),
    Worktree(WorktreeId),
    WorktreeSnapshot(WorktreeSnapshotId),
    WorktreeTransition(WorktreeTransitionId),
    IntegrationEvent(IntegrationEventId),
    RecoveryCaptureRequest(RecoveryCaptureRequestId),
    RecoveryBundle(RecoveryBundleId),
    RecoveryApplication(RecoveryApplicationId),
    Task(TaskId),
    Workstream(WorkstreamId),
    ExecutionLane(ExecutionLaneId),
    WorkEpisode(WorkEpisodeId),
    Attempt(AttemptId),
    CompetingAttemptGroup(CompetingAttemptGroupId),
    ExperimentRun(ExperimentRunId),
    Atom(AtomId),
    Procedure(ProcedureId),
    RevisionProposal(RevisionProposalId),
    CoreMembership(CoreMembershipId),
    WikiProjection(WikiProjectionId),
    CoreProjection(CoreProjectionId),
    WorkArtifact(WorkArtifactId),
    DuplicateGroup(DuplicateGroupId),
    Cas(CasId),
}

impl AnyPublicId {
    pub const fn family(self) -> &'static str {
        match self {
            Self::SourceObservation(_) => "obs",
            Self::HostOccurrence(_) => "occ",
            Self::SourceReceipt(_) => "src",
            Self::CaptureReceipt(_) => "cap",
            Self::CaptureOutageInterval(_) => "outage",
            Self::Operation(_) => "op",
            Self::ScopeEffect(_) => "se",
            Self::WorkBindingRevision(_) => "wb",
            Self::Repository(_) => "repo",
            Self::Worktree(_) => "wt",
            Self::WorktreeSnapshot(_) => "wts",
            Self::WorktreeTransition(_) => "wtt",
            Self::IntegrationEvent(_) => "int",
            Self::RecoveryCaptureRequest(_) => "recreq",
            Self::RecoveryBundle(_) => "rec",
            Self::RecoveryApplication(_) => "recapp",
            Self::Task(_) => "task",
            Self::Workstream(_) => "ws",
            Self::ExecutionLane(_) => "lane",
            Self::WorkEpisode(_) => "ep",
            Self::Attempt(_) => "att",
            Self::CompetingAttemptGroup(_) => "cmp",
            Self::ExperimentRun(_) => "run",
            Self::Atom(_) => "atom",
            Self::Procedure(_) => "proc",
            Self::RevisionProposal(_) => "proposal",
            Self::CoreMembership(_) => "coremem",
            Self::WikiProjection(_) => "wiki",
            Self::CoreProjection(_) => "core",
            Self::WorkArtifact(_) => "art",
            Self::DuplicateGroup(_) => "dup",
            Self::Cas(_) => "cas",
        }
    }
}

impl FromStr for AnyPublicId {
    type Err = IdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (family, _) = value
            .split_once(':')
            .ok_or(IdParseError::MissingSeparator)?;
        match family {
            "obs" => Ok(Self::SourceObservation(value.parse()?)),
            "occ" => Ok(Self::HostOccurrence(value.parse()?)),
            "src" => Ok(Self::SourceReceipt(value.parse()?)),
            "cap" => Ok(Self::CaptureReceipt(value.parse()?)),
            "outage" => Ok(Self::CaptureOutageInterval(value.parse()?)),
            "op" => Ok(Self::Operation(value.parse()?)),
            "se" => Ok(Self::ScopeEffect(value.parse()?)),
            "wb" => Ok(Self::WorkBindingRevision(value.parse()?)),
            "repo" => Ok(Self::Repository(value.parse()?)),
            "wt" => Ok(Self::Worktree(value.parse()?)),
            "wts" => Ok(Self::WorktreeSnapshot(value.parse()?)),
            "wtt" => Ok(Self::WorktreeTransition(value.parse()?)),
            "int" => Ok(Self::IntegrationEvent(value.parse()?)),
            "recreq" => Ok(Self::RecoveryCaptureRequest(value.parse()?)),
            "rec" => Ok(Self::RecoveryBundle(value.parse()?)),
            "recapp" => Ok(Self::RecoveryApplication(value.parse()?)),
            "task" => Ok(Self::Task(value.parse()?)),
            "ws" => Ok(Self::Workstream(value.parse()?)),
            "lane" => Ok(Self::ExecutionLane(value.parse()?)),
            "ep" => Ok(Self::WorkEpisode(value.parse()?)),
            "att" => Ok(Self::Attempt(value.parse()?)),
            "cmp" => Ok(Self::CompetingAttemptGroup(value.parse()?)),
            "run" => Ok(Self::ExperimentRun(value.parse()?)),
            "atom" => Ok(Self::Atom(value.parse()?)),
            "proc" => Ok(Self::Procedure(value.parse()?)),
            "proposal" => Ok(Self::RevisionProposal(value.parse()?)),
            "coremem" => Ok(Self::CoreMembership(value.parse()?)),
            "wiki" => Ok(Self::WikiProjection(value.parse()?)),
            "core" => Ok(Self::CoreProjection(value.parse()?)),
            "art" => Ok(Self::WorkArtifact(value.parse()?)),
            "dup" => Ok(Self::DuplicateGroup(value.parse()?)),
            "cas" => Ok(Self::Cas(value.parse()?)),
            _ => Err(IdParseError::UnknownFamily),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizeTarget {
    Atom(AtomId),
    Procedure(ProcedureId),
    CoreMembership(CoreMembershipId),
}

impl TryFrom<AnyPublicId> for OrganizeTarget {
    type Error = IdParseError;

    fn try_from(value: AnyPublicId) -> Result<Self, Self::Error> {
        match value {
            AnyPublicId::Atom(id) => Ok(Self::Atom(id)),
            AnyPublicId::Procedure(id) => Ok(Self::Procedure(id)),
            AnyPublicId::CoreMembership(id) => Ok(Self::CoreMembership(id)),
            AnyPublicId::WikiProjection(_) | AnyPublicId::CoreProjection(_) => {
                Err(IdParseError::ProjectionNotOrganizable)
            }
            _ => Err(IdParseError::WrongFamily),
        }
    }
}

impl FromStr for OrganizeTarget {
    type Err = IdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.parse::<AnyPublicId>()?)
    }
}
