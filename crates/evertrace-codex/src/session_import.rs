use serde::Deserialize;
use std::path::{Component, Path, PathBuf};

pub const MAX_RECORD_BYTES: usize = 64 * 1024;

pub fn namespace_from_header(
    call: &evertrace_domain::evidence::SourceLocalNativeCall,
    bytes: &[u8],
    device: u64,
    inode: u64,
    file_length: u64,
) -> Result<evertrace_domain::evidence::SourceLocalNamespaceWitness, SessionMetadataError> {
    use evertrace_domain::evidence::{
        SourceLocalNamespace, SourceLocalNamespaceWitness, SourceLocalProfile,
    };
    let path = call
        .transcript_path
        .as_deref()
        .ok_or(SessionMetadataError)?;
    let (_, relative) = native_session_path(path)?;
    let name = relative
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(SessionMetadataError)?;
    let (thread, rollout) = rollout_ids_from_name(name)?;
    let header = parse_session_header(name, bytes)?;
    if header.payload.session_id.as_deref() != Some(call.session_id.as_str())
        || call.agent_id.as_ref().is_some_and(|agent| *agent != thread)
    {
        return Err(SessionMetadataError);
    }
    let witness = SourceLocalNamespaceWitness {
        namespace: SourceLocalNamespace {
            profile: SourceLocalProfile::NativeHookV1,
            root_session: call.session_id.clone(),
            thread,
            rollout,
        },
        transcript_path: path.into(),
        filesystem_device: device,
        filesystem_inode: inode,
        observed_file_length: file_length,
        metadata_length: u32::try_from(bytes.len()).map_err(|_| SessionMetadataError)?,
    };
    witness.validate().map_err(|_| SessionMetadataError)?;
    Ok(witness)
}

pub fn native_session_path(transcript: &str) -> Result<(PathBuf, PathBuf), SessionMetadataError> {
    let path = Path::new(transcript);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(SessionMetadataError);
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(SessionMetadataError)?;
    if session_id_from_name(file_name).is_err() {
        return Err(SessionMetadataError);
    }
    let day = path.parent().ok_or(SessionMetadataError)?;
    let month = day.parent().ok_or(SessionMetadataError)?;
    let year = month.parent().ok_or(SessionMetadataError)?;
    let root = year.parent().ok_or(SessionMetadataError)?;
    if root.file_name().and_then(|value| value.to_str()) != Some("sessions") {
        return Err(SessionMetadataError);
    }
    if !numeric_component(year, 4) || !numeric_component(month, 2) || !numeric_component(day, 2) {
        return Err(SessionMetadataError);
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SessionMetadataError)?
        .to_path_buf();
    Ok((root.to_path_buf(), relative))
}

fn numeric_component(path: &Path, width: usize) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("unsupported native session metadata")]
pub struct SessionMetadataError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetaRecord {
    #[serde(rename = "ordinal")]
    pub _ordinal: Option<u64>,
    #[serde(rename = "timestamp")]
    pub _timestamp: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub payload: SessionMetaPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetaPayload {
    pub id: String,
    #[serde(rename = "session_id")]
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    pub originator: Option<String>,
    #[serde(rename = "cli_version")]
    pub _cli_version: Option<String>,
    #[serde(rename = "source")]
    pub _source: Option<serde::de::IgnoredAny>,
    pub model_provider: Option<String>,
    #[serde(rename = "timestamp")]
    pub _payload_timestamp: Option<String>,
    #[serde(rename = "agent_nickname")]
    pub _agent_nickname: Option<serde::de::IgnoredAny>,
    #[serde(rename = "agent_path")]
    pub _agent_path: Option<serde::de::IgnoredAny>,
    #[serde(rename = "context_window")]
    pub _context_window: Option<serde::de::IgnoredAny>,
    #[serde(rename = "history_mode")]
    pub _history_mode: Option<serde::de::IgnoredAny>,
    #[serde(rename = "multi_agent_version")]
    pub _multi_agent_version: Option<serde::de::IgnoredAny>,
    #[serde(rename = "parent_thread_id")]
    pub _parent_thread_id: Option<serde::de::IgnoredAny>,
    #[serde(rename = "thread_source")]
    pub _thread_source: Option<serde::de::IgnoredAny>,
    #[serde(rename = "base_instructions")]
    pub _base_instructions: Option<serde::de::IgnoredAny>,
    #[serde(rename = "instructions")]
    pub _instructions: Option<serde::de::IgnoredAny>,
    #[serde(rename = "forked_from_id")]
    pub _forked_from_id: Option<serde::de::IgnoredAny>,
    #[serde(rename = "forked_from_ordinal_exclusive")]
    pub _forked_from_ordinal_exclusive: Option<serde::de::IgnoredAny>,
    #[serde(rename = "agent_role", alias = "agent_type")]
    pub _agent_role: Option<serde::de::IgnoredAny>,
    #[serde(rename = "dynamic_tools")]
    pub _dynamic_tools: Option<serde::de::IgnoredAny>,
    #[serde(rename = "selected_capability_roots")]
    pub _selected_capability_roots: Option<serde::de::IgnoredAny>,
    #[serde(rename = "memory_mode")]
    pub _memory_mode: Option<serde::de::IgnoredAny>,
    #[serde(rename = "history_base")]
    pub _history_base: Option<serde::de::IgnoredAny>,
    #[serde(rename = "subagent_history_start_ordinal")]
    pub _subagent_history_start_ordinal: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "deserialize_session_git")]
    pub git: SessionGit,
}

#[derive(Default)]
pub enum SessionGit {
    #[default]
    Missing,
    Object(SessionGitObject),
    Null,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGitObject {
    pub commit_hash: Option<String>,
    pub branch: Option<String>,
    pub repository_url: Option<String>,
}

fn deserialize_session_git<'de, D>(deserializer: D) -> Result<SessionGit, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<SessionGitObject>::deserialize(deserializer)
        .map(|value| value.map_or(SessionGit::Null, SessionGit::Object))
}

// Fixed rust-v0.153.4 rollout basename. The catalog key remains the thread,
// not the optional distinct rollout suffix and not the shared Hook session.
pub fn rollout_ids_from_name(name: &str) -> Result<(String, String), SessionMetadataError> {
    let core = name
        .strip_prefix("rollout-")
        .and_then(|value| value.strip_suffix(".jsonl"))
        .ok_or(SessionMetadataError)?;
    let timestamp = core.get(..19).ok_or(SessionMetadataError)?;
    if !valid_rollout_timestamp(timestamp) || core.get(19..20) != Some("-") {
        return Err(SessionMetadataError);
    }
    let ids = core.get(20..).ok_or(SessionMetadataError)?;
    let (thread, rollout) = ids.split_once('_').unwrap_or((ids, ids));
    if !native_uuid(thread) || !native_uuid(rollout) {
        return Err(SessionMetadataError);
    }
    Ok((thread.to_owned(), rollout.to_owned()))
}

fn native_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_rollout_timestamp(value: &str) -> bool {
    if value.len() != 19
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 | 13 | 16 => byte == b'-',
            10 => byte == b'T',
            _ => byte.is_ascii_digit(),
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u32>().unwrap_or(u32::MAX);
    let year = number(0..4);
    let month = number(5..7);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&number(8..10))
        && number(11..13) < 24
        && number(14..16) < 60
        && number(17..19) < 60
}

pub fn session_id_from_name(name: &str) -> Result<String, SessionMetadataError> {
    rollout_ids_from_name(name).map(|(thread, _)| thread)
}

pub fn parse_session_header(
    name: &str,
    bytes: &[u8],
) -> Result<SessionMetaRecord, SessionMetadataError> {
    let (thread, _) = rollout_ids_from_name(name)?;
    let header: SessionMetaRecord =
        serde_json::from_slice(bytes).map_err(|_| SessionMetadataError)?;
    if header.record_type != "session_meta"
        || header.payload.id != thread
        || header
            .payload
            .session_id
            .as_deref()
            .is_some_and(|id| !native_uuid(id))
    {
        return Err(SessionMetadataError);
    }
    Ok(header)
}
