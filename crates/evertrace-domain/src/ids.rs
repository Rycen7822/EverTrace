use std::{fmt, marker::PhantomData, str::FromStr};

use serde::de::{self, Unexpected, Visitor};
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
    if !uuid_text_is_canonical(uuid, payload) {
        return Err(IdParseError::NonCanonicalUuid);
    }
    Ok(uuid)
}

pub(crate) fn uuid_text_is_canonical(uuid: Uuid, value: &str) -> bool {
    let mut canonical = [0_u8; 36];
    uuid.hyphenated().encode_lower(&mut canonical);
    canonical.as_slice() == value.as_bytes()
}

struct FromStrVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for FromStrVisitor<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value.parse().map_err(E::custom)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let value = std::str::from_utf8(value)
            .map_err(|_| E::invalid_value(Unexpected::Bytes(value), &self))?;
        self.visit_str(value)
    }
}

pub(crate) fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    deserializer.deserialize_string(FromStrVisitor(PhantomData))
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
                let mut text = [0_u8; $prefix.len() + 37];
                let prefix = $prefix.as_bytes();
                let payload_start = prefix.len() + 1;
                text[..prefix.len()].copy_from_slice(prefix);
                text[prefix.len()] = b':';
                self.0.hyphenated().encode_lower(&mut text[payload_start..]);
                serializer.serialize_str(std::str::from_utf8(&text).expect("ID text is ASCII"))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                $crate::ids::deserialize_from_str(deserializer)
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
                let mut text = [0_u8; 36];
                serializer.serialize_str(self.0.hyphenated().encode_lower(&mut text))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                $crate::ids::deserialize_from_str(deserializer)
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
                let mut text = [0_u8; $prefix.len() + 65];
                let prefix = $prefix.as_bytes();
                let payload_start = prefix.len() + 1;
                text[..prefix.len()].copy_from_slice(prefix);
                text[prefix.len()] = b':';
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for (index, byte) in self.0.iter().enumerate() {
                    text[payload_start + index * 2] = HEX[(byte >> 4) as usize];
                    text[payload_start + index * 2 + 1] = HEX[(byte & 0x0f) as usize];
                }
                serializer.serialize_str(std::str::from_utf8(&text).expect("ID text is ASCII"))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                $crate::ids::deserialize_from_str(deserializer)
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
uuid_id!(ProcedureUsageId, "puse");
uuid_id!(ProcedureNegativeEvidenceId, "pneg");
uuid_id!(SemanticDigestId, "sdig");
uuid_id!(SemanticDerivationRunId, "srun");
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
uuid_id!(OperationBurstId, "burst");
uuid_id!(AttemptId, "att");
uuid_id!(CompetingAttemptGroupId, "cmp");
uuid_id!(ExperimentRunId, "run");
uuid_id!(ResultEvidenceId, "result");
uuid_id!(AtomId, "atom");
uuid_id!(ProcedureId, "proc");
uuid_id!(RevisionProposalId, "proposal");
uuid_id!(CoreMembershipId, "coremem");
digest_id!(WikiProjectionId, "wiki");
digest_id!(CoreProjectionId, "core");
digest_id!(ScenarioId, "scenario");
uuid_id!(WorkArtifactId, "art");
uuid_id!(DuplicateGroupId, "dup");
uuid_id!(RecallNeedId, "need");
uuid_id!(PresentationAttemptId, "present");
digest_id!(CasId, "cas");
internal_uuid_id!(CommandId);
internal_uuid_id!(JobId);
internal_uuid_id!(RequestId);

macro_rules! impl_new_v7 {
    ($($name:ident),+ $(,)?) => {
        $(
            impl $name {
                pub fn new_v7() -> Self {
                    Self(Uuid::now_v7())
                }
            }
        )+
    };
}

impl_new_v7!(
    OperationId,
    CaptureReceiptId,
    CaptureOutageIntervalId,
    ExecutionLaneId,
    ScopeEffectId,
    WorkBindingRevisionId,
    ProcedureUsageId,
    ProcedureNegativeEvidenceId,
    SemanticDigestId,
    SemanticDerivationRunId,
    DuplicateGroupId,
    RepositoryId,
    WorktreeId,
    WorktreeSnapshotId,
    WorktreeTransitionId,
    IntegrationEventId,
    RecoveryCaptureRequestId,
    RecoveryBundleId,
    RecoveryApplicationId,
    TaskId,
    WorkstreamId,
    WorkEpisodeId,
    AttemptId,
    CompetingAttemptGroupId,
    OperationBurstId,
    ExperimentRunId,
    ResultEvidenceId,
    AtomId,
    ProcedureId,
    RevisionProposalId,
    CoreMembershipId,
    WorkArtifactId,
    RecallNeedId,
    PresentationAttemptId,
);

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
    OperationBurst(OperationBurstId),
    Attempt(AttemptId),
    CompetingAttemptGroup(CompetingAttemptGroupId),
    ExperimentRun(ExperimentRunId),
    ResultEvidence(ResultEvidenceId),
    Atom(AtomId),
    Procedure(ProcedureId),
    RevisionProposal(RevisionProposalId),
    CoreMembership(CoreMembershipId),
    SemanticDigest(SemanticDigestId),
    SemanticDerivationRun(SemanticDerivationRunId),
    WikiProjection(WikiProjectionId),
    CoreProjection(CoreProjectionId),
    Scenario(ScenarioId),
    WorkArtifact(WorkArtifactId),
    DuplicateGroup(DuplicateGroupId),
    Cas(CasId),
}

#[cfg(test)]
mod tests {
    use super::{RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId};
    use uuid::Variant;

    #[test]
    fn public_uuid_macro_constructs_rfc_uuid_v7() {
        for value in [
            RecoveryCaptureRequestId::new_v7().as_uuid(),
            RecoveryBundleId::new_v7().as_uuid(),
            RecoveryApplicationId::new_v7().as_uuid(),
        ] {
            assert_eq!(value.get_version_num(), 7);
            assert_eq!(value.get_variant(), Variant::RFC4122);
        }
    }
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
            Self::OperationBurst(_) => "burst",
            Self::Attempt(_) => "att",
            Self::CompetingAttemptGroup(_) => "cmp",
            Self::ExperimentRun(_) => "run",
            Self::ResultEvidence(_) => "result",
            Self::Atom(_) => "atom",
            Self::Procedure(_) => "proc",
            Self::RevisionProposal(_) => "proposal",
            Self::CoreMembership(_) => "coremem",
            Self::SemanticDigest(_) => "sdig",
            Self::SemanticDerivationRun(_) => "srun",
            Self::WikiProjection(_) => "wiki",
            Self::CoreProjection(_) => "core",
            Self::Scenario(_) => "scenario",
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
            "burst" => Ok(Self::OperationBurst(value.parse()?)),
            "att" => Ok(Self::Attempt(value.parse()?)),
            "cmp" => Ok(Self::CompetingAttemptGroup(value.parse()?)),
            "run" => Ok(Self::ExperimentRun(value.parse()?)),
            "result" => Ok(Self::ResultEvidence(value.parse()?)),
            "atom" => Ok(Self::Atom(value.parse()?)),
            "proc" => Ok(Self::Procedure(value.parse()?)),
            "proposal" => Ok(Self::RevisionProposal(value.parse()?)),
            "coremem" => Ok(Self::CoreMembership(value.parse()?)),
            "sdig" => Ok(Self::SemanticDigest(value.parse()?)),
            "srun" => Ok(Self::SemanticDerivationRun(value.parse()?)),
            "wiki" => Ok(Self::WikiProjection(value.parse()?)),
            "core" => Ok(Self::CoreProjection(value.parse()?)),
            "scenario" => Ok(Self::Scenario(value.parse()?)),
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

#[cfg(test)]
mod text_deserializer_tests {
    use super::{IdParseError, TaskId, split_family, validate_uuid};
    use crate::revision::{RevisionId, RevisionIdError};
    use serde::Deserialize;
    use serde::de::Visitor;
    use serde::de::value::{
        BorrowedBytesDeserializer, BorrowedStrDeserializer, BytesDeserializer, Error as ValueError,
        StrDeserializer, StringDeserializer,
    };
    use std::str::FromStr;
    use uuid::Uuid;

    const TASK_TEXT: &str = "task:01890f47-6a4a-7cc1-98b9-01890f476a4a";
    const UUID_V4_UPPERCASE: &str = "550E8400-E29B-41D4-A716-446655440000";

    #[test]
    fn text_visitor_accepts_serde_string_and_utf8_byte_value_forms() {
        let expected = TaskId::from_str(TASK_TEXT).expect("task ID");
        let forms = [
            TaskId::deserialize(BorrowedStrDeserializer::<ValueError>::new(TASK_TEXT)),
            TaskId::deserialize(StrDeserializer::<ValueError>::new(TASK_TEXT)),
            TaskId::deserialize(StringDeserializer::<ValueError>::new(TASK_TEXT.to_owned())),
            TaskId::deserialize(BorrowedBytesDeserializer::<ValueError>::new(
                TASK_TEXT.as_bytes(),
            )),
            TaskId::deserialize(BytesDeserializer::<ValueError>::new(TASK_TEXT.as_bytes())),
        ];
        for form in forms {
            assert_eq!(form.expect("string or UTF-8 byte form"), expected);
        }
        assert_eq!(
            super::FromStrVisitor::<TaskId>(std::marker::PhantomData)
                .visit_byte_buf::<ValueError>(TASK_TEXT.as_bytes().to_vec())
                .expect("owned bytes"),
            expected
        );
    }

    #[test]
    fn text_visitor_preserves_string_visitor_errors_for_bad_utf8() {
        let invalid_utf8 = [0xff, 0xfe];
        let old_error =
            String::deserialize(BorrowedBytesDeserializer::<ValueError>::new(&invalid_utf8))
                .expect_err("invalid UTF-8")
                .to_string();
        let new_error =
            TaskId::deserialize(BorrowedBytesDeserializer::<ValueError>::new(&invalid_utf8))
                .expect_err("invalid UTF-8")
                .to_string();
        assert_eq!(new_error, old_error);
        assert_eq!(new_error, "invalid value: byte array, expected a string");
    }

    #[test]
    fn uuid_parsers_match_the_previous_canonical_and_validation_order() {
        fn old_task_parse(value: &str) -> Result<Uuid, IdParseError> {
            let payload = split_family(value, "task")?;
            let uuid = Uuid::parse_str(payload).map_err(|_| IdParseError::InvalidUuid)?;
            validate_uuid(uuid)?;
            if uuid.hyphenated().to_string() != payload {
                return Err(IdParseError::NonCanonicalUuid);
            }
            Ok(uuid)
        }

        fn old_revision_parse(value: &str) -> Result<RevisionId, RevisionIdError> {
            let uuid = Uuid::parse_str(value).map_err(|_| RevisionIdError::InvalidUuid)?;
            if uuid.hyphenated().to_string() != value {
                return Err(RevisionIdError::InvalidUuid);
            }
            RevisionId::from_uuid(uuid)
        }

        let compact = "01890f476a4a7cc198b901890f476a4a";
        let task_inputs = [
            TASK_TEXT.to_owned(),
            format!("task:{}", TASK_TEXT[5..].to_uppercase()),
            format!("task:{compact}"),
            format!("ws:{}", &TASK_TEXT[5..]),
            format!("task:{UUID_V4_UPPERCASE}"),
            "task:01890f47-6a4a-7cc1-18b9-01890f476a4a".to_owned(),
        ];
        for input in task_inputs {
            let old = old_task_parse(&input);
            let new = TaskId::from_str(&input).map(TaskId::as_uuid);
            assert_eq!(new, old, "input classification changed for {input:?}");
        }

        let revision_inputs = [
            TASK_TEXT[5..].to_owned(),
            TASK_TEXT[5..].to_uppercase(),
            compact.to_owned(),
            UUID_V4_UPPERCASE.to_owned(),
            "01890f47-6a4a-7cc1-18b9-01890f476a4a".to_owned(),
        ];
        for input in revision_inputs {
            let old = old_revision_parse(&input);
            let new = RevisionId::from_str(&input);
            assert_eq!(new, old, "input classification changed for {input:?}");
        }
    }
}
