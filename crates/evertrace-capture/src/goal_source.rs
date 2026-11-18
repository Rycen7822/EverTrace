//! Read a supported host's own goal object. Locator fields never grant source authority.

use std::{
    fs,
    io::Read,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    time::{Duration, Instant},
};

use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceArchiveMode,
    SourceObservation, SourceReceipt, SourceRevisionMode, SourceRole, hex, payload_fingerprint,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tungstenite::{Message, WebSocket, client::client_with_config, protocol::WebSocketConfig};

use crate::{CaptureRecordInput, ConfinedRoot, DeviceKey, protect::protect};

// Exact external executable and goal/get format; this is not an ordinary Host/namespace qualification.
pub const SOURCE_REVISION: &str =
    "host-goal-jsonrpc-0.166.0:b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8";
pub const ELIGIBLE_EVENTS: &str = "host-goal-get-jsonrpc-v1";
pub const ADAPTER_REVISION: u32 = 1;
const LIMIT: usize = 65_536;
pub const IDENTITY_DOMAIN: &str = "native-host-goal-v1";

#[derive(Debug, thiserror::Error)]
#[error("native goal source is unavailable or unverified")]
pub struct GoalSourceError;
type Result<T> = std::result::Result<T, GoalSourceError>;

pub fn is_source_revision(revision: &str) -> bool {
    revision == SOURCE_REVISION
        || revision == publisher_revision(EXECUTION_BINARY_SHA256)
        || revision == publisher_revision(CONTEXT_BINARY_SHA256)
}

pub fn adapter_version(revision: &str) -> Result<String> {
    if !is_source_revision(revision) {
        return Err(GoalSourceError);
    }
    Ok(format!("{revision}:capture-{ADAPTER_REVISION}"))
}

fn publisher_revision(fingerprint: &str) -> String {
    let (abi, _) = SOURCE_REVISION.rsplit_once(':').expect("fixed goal ABI");
    format!("{abi}:{fingerprint}")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Goal {
    thread_id: String,
    objective: String,
    status: String,
    token_budget: Option<i64>,
    tokens_used: i64,
    time_used_seconds: i64,
    created_at: i64,
    updated_at: i64,
}

impl Goal {
    fn root_ref(&self) -> String {
        format!("native-host-goal:{}", self.thread_id)
    }

    fn epoch(&self) -> (&str, &str, i64) {
        (&self.thread_id, &self.objective, self.created_at)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    id: u64,
    result: GoalResult,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoalResult {
    goal: Option<Goal>,
}

/// Decode the unchanged external response; this alone supplies no admission or authority.
fn decode(raw: &[u8]) -> Result<Option<Goal>> {
    if raw.len() > LIMIT {
        return Err(GoalSourceError);
    }
    let reply: Reply = serde_json::from_slice(raw).map_err(|_| GoalSourceError)?;
    if reply.id != 2 {
        return Err(GoalSourceError);
    }
    if let Some(goal) = &reply.result.goal {
        let id = uuid::Uuid::parse_str(&goal.thread_id).map_err(|_| GoalSourceError)?;
        if id.is_nil()
            || id.hyphenated().to_string() != goal.thread_id
            || goal.objective.trim().is_empty()
            || goal.objective.len() > 4096
            || goal.created_at < 0
            || goal.updated_at < goal.created_at
            || goal.tokens_used < 0
            || goal.time_used_seconds < 0
            || goal.token_budget.is_some_and(|value| value <= 0)
            || !matches!(
                goal.status.as_str(),
                "active" | "paused" | "blocked" | "usageLimited" | "budgetLimited" | "complete"
            )
        {
            return Err(GoalSourceError);
        }
    }
    Ok(reply.result.goal)
}

/// Candidate text is not a root designation; only a revalidated publisher can supply that witness.
pub fn observed_goal(raw: &[u8]) -> Result<Option<(String, String)>> {
    Ok(decode(raw)?.map(|goal| (goal.root_ref(), goal.objective)))
}

/// Compare already admitted goal observations, independent of lifecycle status.
/// Creation time has only second precision in this source ABI.
pub fn same_goal_epoch(archived: &[u8], current: &[u8]) -> bool {
    match (decode(archived), decode(current)) {
        (Ok(Some(old)), Ok(Some(new))) => old.epoch() == new.epoch(),
        _ => false,
    }
}

/// A current publisher and the protected original bytes have independently agreed on this root.
pub struct RootGoal {
    reference: String,
    objective: String,
    completion_intent: bool,
    created_at: i64,
    publisher_instance: String,
    publisher_executable: (u64, u64),
    thread: String,
}

impl RootGoal {
    pub fn source_ref(&self) -> &str {
        &self.reference
    }

    pub fn objective(&self) -> &str {
        &self.objective
    }

    /// Native goal intent only; not a verifier result or a Task/Episode lifecycle transition.
    pub const fn completion_intent(&self) -> bool {
        self.completion_intent
    }

    /// Compare only the state of an already bound observation. This ABI exposes creation time in seconds, not a goal ID.
    pub fn matches_bound_state(&self, protected: &[u8], complete: bool) -> bool {
        decode(protected).is_ok_and(|goal| {
            goal.is_some_and(|goal| {
                goal.epoch() == (&*self.thread, &*self.objective, self.created_at)
                    && (goal.status == "complete") == complete
            })
        })
    }

    pub fn publisher_pid(&self) -> u32 {
        self.publisher_instance
            .split(':')
            .nth(3)
            .and_then(|value| value.parse().ok())
            .expect("revalidated publisher instance")
    }

    pub fn matches_publisher(&self, instance: &str, executable: (u64, u64)) -> bool {
        self.publisher_instance == instance && self.publisher_executable == executable
    }

    /// Only an independently revalidated goal can use this locator match as
    /// part of a Work scope witness. It does not resolve semantic assignment.
    pub fn matches_execution(&self, receipt: &SourceReceipt) -> bool {
        execution_peer_matches(&self.publisher_instance, &self.thread, receipt)
    }
}

/// Candidate selection only: these stored locators do not authenticate a publisher.
pub fn same_execution_context(goal: &SourceReceipt, execution: &SourceReceipt) -> bool {
    is_source_revision(goal.source_revision.as_str())
        && goal.identity_domain == IDENTITY_DOMAIN
        && execution_peer_matches(
            goal.source_instance_id.as_str(),
            &goal.source_session_ref,
            execution,
        )
}

fn execution_peer_matches(instance: &str, thread: &str, receipt: &SourceReceipt) -> bool {
    let Some(goal_peer) = instance.strip_prefix("host-goal:") else {
        return false;
    };
    let Some((peer, _)) = receipt
        .source_instance_id
        .as_str()
        .strip_prefix("native-events:")
        .and_then(|value| value.split_once(":capture:"))
    else {
        return false;
    };
    peer == goal_peer
        && receipt.source_session_ref == thread
        && crate::execution_source::Profile::from_revision(receipt.parser_revision)
            == Some(crate::execution_source::Profile::Context)
}

/// Current publisher identity for configuration read authority only; not a live goal designation.
pub fn policy_publisher(receipt: &SourceReceipt) -> Result<(u32, String, (u64, u64))> {
    if !is_source_revision(receipt.source_revision.as_str())
        || receipt.identity_domain != IDENTITY_DOMAIN
    {
        return Err(GoalSourceError);
    }
    let pid = receipt
        .source_instance_id
        .as_str()
        .split(':')
        .nth(3)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(GoalSourceError)?;
    let peer = peer(pid)?;
    let (_, publisher) =
        connect_publisher(&peer.endpoint, Instant::now() + Duration::from_secs(3))?;
    let instance = publisher.instance("host-goal")?;
    if instance != receipt.source_instance_id.as_str()
        || publisher_revision(publisher.fingerprint) != receipt.source_revision.as_str()
    {
        return Err(GoalSourceError);
    }
    publisher.revalidate()?;
    Ok((pid, instance, peer.executable))
}

/// Re-read the actual publisher, not a claimed role, profile label or copied historical payload.
pub fn revalidate(
    receipt: &SourceReceipt,
    observation: &SourceObservation,
    bytes: &[u8],
    key: &DeviceKey,
) -> Result<RootGoal> {
    if !is_source_revision(receipt.source_revision.as_str())
        || receipt.identity_domain != IDENTITY_DOMAIN
        || receipt.source_kind != EvidenceSourceKind::Other
        || receipt.protection_key_generation != key.generation()
        || receipt.identity_strength != IdentityStrength::SynthesizedBestEffort
        || observation.identity_strength != IdentityStrength::SynthesizedBestEffort
        || receipt.observation_role != ObservationRole::StateProbe
        || observation.observation_role != ObservationRole::StateProbe
        || observation.correlation.admission != CorrelationAdmission::Unavailable
        || receipt.source_sequence != 0
        || receipt.source_sequence_origin != Some(0)
        || receipt.source_revision_mode != SourceRevisionMode::Append
        || receipt.previous_source_revision.is_some()
        || receipt.close_watermark.is_some()
        || receipt.source_byte_range.is_some()
    {
        return Err(GoalSourceError);
    }
    let pid = receipt
        .source_instance_id
        .as_str()
        .split(':')
        .nth(3)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(GoalSourceError)?;
    let publisher = peer(pid)?;
    let current = read(&publisher.endpoint, &receipt.source_session_ref)?.ok_or(GoalSourceError)?;
    if current.instance != receipt.source_instance_id.as_str()
        || current.reference != receipt.source_ref
        || current.revision != receipt.source_revision.as_str()
    {
        return Err(GoalSourceError);
    }
    let protected = protect(&current.raw, key).map_err(|_| GoalSourceError)?;
    let archive = match protected.archive_mode() {
        crate::ArchiveMode::Exact => SourceArchiveMode::Exact,
        crate::ArchiveMode::Redacted => SourceArchiveMode::Redacted,
    };
    if protected.protected_bytes() != bytes
        || protected.raw_length() != receipt.original_length
        || protected.detector_revision() != receipt.detector_revision
        || protected.redaction_revision() != receipt.redaction_revision
        || protected
            .protected_secret_digest()
            .map(|digest| evertrace_domain::evidence::hex(&digest))
            != receipt.protected_secret_digest
        || archive != receipt.archive_mode
    {
        return Err(GoalSourceError);
    }
    let fingerprint = payload_fingerprint(
        receipt.canonicalization_revision,
        bytes,
        protected.protected_secret_digest(),
    )
    .map_err(|_| GoalSourceError)?;
    if observation.source_receipt_ref != receipt.source_receipt_id
        || observation.source_instance_id != receipt.source_instance_id
        || observation.source_revision != receipt.source_revision
        || observation.source_record_identity != receipt.source_record_identity
        || observation.payload_fingerprint != hex(&fingerprint)
    {
        return Err(GoalSourceError);
    }
    let goal = decode(&current.raw)?.ok_or(GoalSourceError)?;
    // A redacted archive is not necessarily JSON. Derive the safe field from the independently
    // witnessed original, never from the optional L0 presentation or an unverified caller string.
    let objective = protect(goal.objective.as_bytes(), key).map_err(|_| GoalSourceError)?;
    Ok(RootGoal {
        reference: goal.root_ref(),
        objective: String::from_utf8(objective.protected_bytes().to_vec())
            .map_err(|_| GoalSourceError)?,
        completion_intent: goal.status == "complete",
        created_at: goal.created_at,
        publisher_instance: receipt.source_instance_id.as_str().to_owned(),
        publisher_executable: publisher.executable,
        thread: receipt.source_session_ref.clone(),
    })
}

// Private construction prevents typed Hook/SDK input from manufacturing a verified source observation.
pub struct Observation {
    raw: Vec<u8>,
    instance: String,
    reference: String,
    thread: String,
    revision: String,
}

// Canonical whole-ELF fingerprints for the real source formats, including the retained upgrade producer.
const EXECUTION_BINARY_SHA256: &str =
    "87b73337e44523eba731eb9326c96dbcc8a565657cb7de3ee3e36667c258498e";
const CONTEXT_BINARY_SHA256: &str =
    "aa2927a32b6b724d7eb951c2e671ecdbd7ef30d1a34ac5f9d535b694aa73c707";

#[derive(Eq, PartialEq)]
struct Peer {
    pid: u32,
    start: String,
    namespace: u64,
    executable: (u64, u64),
    standalone: bool,
    endpoint: std::path::PathBuf,
}

fn peer(pid: u32) -> Result<Peer> {
    let root = std::path::PathBuf::from(format!("/proc/{pid}"));
    let mut argv = Vec::new();
    fs::File::open(root.join("cmdline"))
        .map_err(|_| GoalSourceError)?
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut argv)
        .map_err(|_| GoalSourceError)?;
    let args = argv.split(|byte| *byte == 0).collect::<Vec<_>>();
    if argv.len() > LIMIT
        || !matches!(args.get(1).copied(), Some(b"app-server" | b"--listen"))
        || args.contains(&b"proxy".as_slice())
    {
        return Err(GoalSourceError);
    }
    let endpoint = args
        .windows(2)
        .find(|pair| pair[0] == b"--listen")
        .and_then(|pair| std::str::from_utf8(pair[1]).ok())
        .and_then(|value| value.strip_prefix("unix://"))
        .ok_or(GoalSourceError)?;
    let endpoint = std::path::PathBuf::from(endpoint);
    if !endpoint.is_absolute() {
        return Err(GoalSourceError);
    }
    let stat = fs::read_to_string(root.join("stat")).map_err(|_| GoalSourceError)?;
    let (_, tail) = stat.rsplit_once(") ").ok_or(GoalSourceError)?;
    let start = tail
        .split_whitespace()
        .nth(19)
        .ok_or(GoalSourceError)?
        .to_owned();
    let namespace = fs::metadata(root.join("ns/pid"))
        .map_err(|_| GoalSourceError)?
        .ino();
    let metadata = fs::metadata(root.join("exe")).map_err(|_| GoalSourceError)?;
    Ok(Peer {
        pid,
        start,
        namespace,
        executable: (metadata.dev(), metadata.ino()),
        standalone: args.get(1).copied() == Some(b"--listen".as_slice()),
        endpoint,
    })
}

fn timeout(stream: &UnixStream, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(GoalSourceError)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| GoalSourceError)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| GoalSourceError)
}

impl Peer {
    fn instance(&self, prefix: &str) -> Result<String> {
        let boot =
            fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| GoalSourceError)?;
        Ok(format!(
            "{prefix}:{}:{}:{}:{}",
            boot.trim(),
            self.namespace,
            self.pid,
            self.start
        ))
    }
}

fn verified_publisher(stream: &UnixStream, deadline: Instant) -> Result<(Peer, &'static str)> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(|_| GoalSourceError)?;
    if credentials.uid.as_raw()
        != fs::metadata("/proc/self")
            .map_err(|_| GoalSourceError)?
            .uid()
    {
        return Err(GoalSourceError);
    }
    let pid = credentials.pid.as_raw_nonzero().get() as u32;
    let before = peer(pid)?;
    let mut file = fs::File::open(format!("/proc/{pid}/exe")).map_err(|_| GoalSourceError)?;
    if file.metadata().map_err(|_| GoalSourceError)?.len() > 512 << 20 {
        return Err(GoalSourceError);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65_536];
    loop {
        if Instant::now() >= deadline {
            return Err(GoalSourceError);
        }
        let count = file.read(&mut buffer).map_err(|_| GoalSourceError)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let actual = format!("{digest:x}", digest = digest.finalize());
    let expected = if before.standalone {
        [EXECUTION_BINARY_SHA256, CONTEXT_BINARY_SHA256]
            .into_iter()
            .find(|expected| *expected == actual)
            .ok_or(GoalSourceError)?
    } else {
        let expected = SOURCE_REVISION.rsplit(':').next().ok_or(GoalSourceError)?;
        if actual != expected {
            return Err(GoalSourceError);
        }
        expected
    };
    Ok((before, expected))
}

pub(crate) struct Publisher {
    peer: Peer,
    fingerprint: &'static str,
    locator: std::path::PathBuf,
    confined: ConfinedRoot,
    locator_identity: (u64, u64),
    endpoint: std::path::PathBuf,
    endpoint_root: Option<ConfinedRoot>,
    endpoint_identity: (u64, u64),
}

impl Publisher {
    pub(crate) fn execution_profile(&self) -> Option<crate::execution_source::Profile> {
        use crate::execution_source::Profile;
        match self.fingerprint {
            EXECUTION_BINARY_SHA256 => Some(Profile::ProcessNative),
            CONTEXT_BINARY_SHA256 => Some(Profile::Context),
            _ => None,
        }
    }

    pub(crate) fn matches_executable(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_file()
                && (metadata.dev(), metadata.ino()) == self.peer.executable
                && self.revalidate().is_ok()
        })
    }

    pub(crate) fn instance(&self, prefix: &str) -> Result<String> {
        self.peer.instance(prefix)
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        self.confined
            .revalidate_stable()
            .map_err(|_| GoalSourceError)?;
        if let Some(root) = &self.endpoint_root {
            root.revalidate_stable().map_err(|_| GoalSourceError)?;
            if fs::read_link(&self.locator).map_err(|_| GoalSourceError)? != self.endpoint {
                return Err(GoalSourceError);
            }
        }
        let after = fs::symlink_metadata(&self.endpoint).map_err(|_| GoalSourceError)?;
        let locator = fs::symlink_metadata(&self.locator).map_err(|_| GoalSourceError)?;
        if peer(self.peer.pid)? != self.peer
            || self.endpoint_identity != (after.dev(), after.ino())
            || self.locator_identity != (locator.dev(), locator.ino())
            || after.uid()
                != fs::metadata("/proc/self")
                    .map_err(|_| GoalSourceError)?
                    .uid()
            || after.mode() & 0o022 != 0
        {
            return Err(GoalSourceError);
        }
        Ok(())
    }
}

pub(crate) fn connect_publisher(path: &Path, deadline: Instant) -> Result<(UnixStream, Publisher)> {
    let parent = path.parent().ok_or(GoalSourceError)?;
    let confined = ConfinedRoot::open_owned_private(parent).map_err(|_| GoalSourceError)?;
    let locator = fs::symlink_metadata(path).map_err(|_| GoalSourceError)?;
    let uid = fs::metadata("/proc/self")
        .map_err(|_| GoalSourceError)?
        .uid();
    if locator.uid() != uid {
        return Err(GoalSourceError);
    }
    // The publisher advertises one owned alias to its shorter, private Unix socket.
    let (endpoint, endpoint_root) = if locator.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|_| GoalSourceError)?;
        let root = ConfinedRoot::open_owned_private(target.parent().ok_or(GoalSourceError)?)
            .map_err(|_| GoalSourceError)?;
        (target, Some(root))
    } else {
        (path.to_path_buf(), None)
    };
    let metadata = fs::symlink_metadata(&endpoint).map_err(|_| GoalSourceError)?;
    if !metadata.file_type().is_socket() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(GoalSourceError);
    }
    let stream = UnixStream::connect(&endpoint).map_err(|_| GoalSourceError)?;
    timeout(&stream, deadline)?;
    let (peer, fingerprint) = verified_publisher(&stream, deadline)?;
    let publisher = Publisher {
        peer,
        fingerprint,
        locator: path.to_path_buf(),
        confined,
        locator_identity: (locator.dev(), locator.ino()),
        endpoint,
        endpoint_root,
        endpoint_identity: (metadata.dev(), metadata.ino()),
    };
    publisher.revalidate()?;
    timeout(&stream, deadline)?;
    Ok((stream, publisher))
}

fn response(socket: &mut WebSocket<UnixStream>, id: u64, deadline: Instant) -> Result<Vec<u8>> {
    for _ in 0..8 {
        timeout(socket.get_ref(), deadline)?;
        let message = socket.read().map_err(|_| GoalSourceError)?;
        if let Message::Text(text) = message {
            let raw = text.as_bytes();
            let body: serde_json::Value =
                serde_json::from_slice(raw).map_err(|_| GoalSourceError)?;
            if body.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                return Ok(raw.to_vec());
            }
        }
    }
    Err(GoalSourceError)
}

fn connect_client(path: &Path, deadline: Instant) -> Result<(WebSocket<UnixStream>, Publisher)> {
    let (stream, publisher) = connect_publisher(path, deadline)?;
    let config = WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0)
        .max_message_size(Some(LIMIT))
        .max_frame_size(Some(LIMIT));
    let (mut socket, _) =
        client_with_config("ws://localhost/", stream, Some(config)).map_err(|_| GoalSourceError)?;
    let initialize = serde_json::json!({"id":1,"method":"initialize","params":{
        "clientInfo":{"name":"evertrace","version":"0.0.0"},"capabilities":{"experimentalApi":true}
    }});
    socket
        .send(Message::text(initialize.to_string()))
        .map_err(|_| GoalSourceError)?;
    let hello: serde_json::Value = serde_json::from_slice(&response(&mut socket, 1, deadline)?)
        .map_err(|_| GoalSourceError)?;
    if hello.get("result").is_none() {
        return Err(GoalSourceError);
    }
    socket
        .send(Message::text(r#"{"method":"initialized","params":{}}"#))
        .map_err(|_| GoalSourceError)?;
    Ok((socket, publisher))
}

/// One bounded, read-only exchange with the actual supported publisher. Never spawn or poll a host.
pub fn read(path: &Path, thread: &str) -> Result<Option<Observation>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let selected = uuid::Uuid::parse_str(thread).map_err(|_| GoalSourceError)?;
    if selected.is_nil() || selected.hyphenated().to_string() != thread {
        return Err(GoalSourceError);
    }
    let (mut socket, publisher) = connect_client(path, deadline)?;
    let request =
        serde_json::json!({"id":2,"method":"thread/goal/get","params":{"threadId":thread}});
    socket
        .send(Message::text(request.to_string()))
        .map_err(|_| GoalSourceError)?;
    let raw = response(&mut socket, 2, deadline)?;
    let goal = decode(&raw)?;
    let request = serde_json::json!({"id":3,"method":"thread/read","params":{"threadId":thread,"includeTurns":false}});
    socket
        .send(Message::text(request.to_string()))
        .map_err(|_| GoalSourceError)?;
    let thread_metadata: serde_json::Value =
        serde_json::from_slice(&response(&mut socket, 3, deadline)?)
            .map_err(|_| GoalSourceError)?;
    let root = thread_metadata
        .pointer("/result/thread")
        .ok_or(GoalSourceError)?;
    // A copied goal in a fork/subagent is not a new root designation.
    if root.get("id").and_then(serde_json::Value::as_str) != Some(thread)
        || root.get("forkedFromId") != Some(&serde_json::Value::Null)
        || root.get("parentThreadId") != Some(&serde_json::Value::Null)
        || !matches!(
            root.get("source").and_then(serde_json::Value::as_str),
            Some("cli" | "exec" | "vscode")
        )
    {
        return Err(GoalSourceError);
    }
    publisher.revalidate()?;
    let Some(goal) = goal else {
        return Ok(None);
    };
    if goal.thread_id != thread {
        return Err(GoalSourceError);
    }
    Ok(Some(Observation {
        raw,
        revision: publisher_revision(publisher.fingerprint),
        instance: publisher.instance("host-goal")?,
        reference: goal.root_ref(),
        thread: goal.thread_id,
    }))
}

/// Read one persisted logical tool request from its measured attempt's actual publisher.
/// This returns source material, never physical argv, verifier or Phase authority.
pub fn read_tool_request(
    observation: &SourceObservation,
    receipt: &SourceReceipt,
    protected: &[u8],
) -> Result<Vec<u8>> {
    let (thread, turn, call) =
        crate::execution_source::tool_request(observation, receipt, protected)
            .ok_or(GoalSourceError)?;
    let pid = observation
        .correlation
        .host_instance_id
        .as_deref()
        .and_then(|instance| instance.split(':').nth(3))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(GoalSourceError)?;
    let peer = peer(pid)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut socket, publisher) = connect_client(&peer.endpoint, deadline)?;
    if !execution_peer_matches(&publisher.instance("host-goal")?, &thread, receipt) {
        return Err(GoalSourceError);
    }
    let request = serde_json::json!({"id":2,"method":"thread/items/read",
        "params":{"threadId":thread,"turnId":turn,"itemIds":[call]}});
    socket
        .send(Message::text(request.to_string()))
        .map_err(|_| GoalSourceError)?;
    let raw = response(&mut socket, 2, deadline)?;
    let reply: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| GoalSourceError)?;
    let entries = reply
        .pointer("/result/data")
        .and_then(serde_json::Value::as_array)
        .filter(|rows| rows.len() == 1)
        .ok_or(GoalSourceError)?;
    let entry = &entries[0];
    let item = &entry["item"];
    if entry["turnId"].as_str() != Some(turn.as_str())
        || item["id"].as_str() != Some(call.as_str())
        || item["type"].as_str() != Some("commandExecution")
        || item["command"]
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 8192)
    {
        return Err(GoalSourceError);
    }
    publisher.revalidate()?;
    Ok(raw)
}

impl Observation {
    pub fn adapter_version(&self) -> String {
        format!("{}:capture-{ADAPTER_REVISION}", self.revision)
    }

    pub(crate) fn into_record(self, manifest: &str) -> CaptureRecordInput {
        CaptureRecordInput {
            spool_record_id: None,
            source_observation_id_hint: None,
            source_instance_id: self.instance,
            source_revision: self.revision,
            source_record_identity: None,
            identity_strength: Some(IdentityStrength::SynthesizedBestEffort),
            source_kind: EvidenceSourceKind::Other,
            identity_domain: IDENTITY_DOMAIN.into(),
            source_ref: self.reference,
            session_ref: self.thread,
            turn_ref: None,
            tool_ref: None,
            source_sequence: 0,
            source_sequence_origin: Some(0),
            task_id: None,
            repository_instance_id: None,
            worktree_instance_id: None,
            source_byte_range: None,
            source_revision_mode: SourceRevisionMode::Append,
            previous_source_revision: None,
            close_watermark: None,
            observation_role: ObservationRole::StateProbe,
            correlation: HostCorrelationEvidence {
                occurrence_schema_version: 1,
                host_instance_id: None,
                host_trace_lineage_id: None,
                host_lane_key: None,
                canonical_event_family: None,
                native_request_id: None,
                physical_execution_ordinal: None,
                pairing_role: ObservationRole::StateProbe,
                field_provenance: vec![],
                adapter_manifest_ref: manifest.into(),
                adapter_revision: ADAPTER_REVISION,
                strong_gate_receipt_ref: None,
                admission: CorrelationAdmission::Unavailable,
                partial_correlation_ref: None,
                possible_duplicate_group_id: None,
            },
            scope_effect_claims: vec![],
            source_local_evidence: None,
            lifecycle: None,
            unsupported_record_classification: None,
            source_role: SourceRole::Host,
            content_trust: ContentTrust::Observed,
            capture_completeness: CaptureCompleteness::Partial,
            surface_eligible: true,
            adapter_revision: ADAPTER_REVISION,
            adapter_manifest_ref: manifest.into(),
            eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
            parser_revision: 1,
            canonicalization_revision: 1,
            event_time_us: None,
            event_time_provenance: None,
            raw_payload: self.raw,
        }
    }
}
