//! Explicit, bounded source canary. Ordinary relays never call this command-producing path.
use std::{
    fs,
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, client::client_with_config, protocol::WebSocketConfig};

use crate::{
    CaptureOutcome, CaptureRuntime, CasDigest, CasStore, RuntimeSnapshot, goal_source, host_events,
};
use evertrace_domain::evidence::HostCorrelationEvidence;

#[derive(Debug, thiserror::Error)]
#[error("execution source canary unavailable")]
pub struct CanaryError;

/// Only a verified live source can construct these measurements. No runtime gate is changed here.
pub struct CanaryFacts {
    pub profile: super::Profile,
    pub measurements: Vec<(String, HostCorrelationEvidence)>,
    pub protected_digest: String,
    pub fork_isolated: bool,
    pub resume_isolated: bool,
    pub replay_deduplicated: bool,
    pub nonidentity_similarity_not_merged: bool,
    pub missing_field_rejected: bool,
    pub field_conflict_rejected: bool,
    _verified: (),
}

type Result<T> = std::result::Result<T, CanaryError>;

struct Capture {
    runtime: CaptureRuntime,
    cas: CasStore,
    manifest: String,
    facts: CanaryFacts,
}

struct Client {
    profile: super::Profile,
    socket: WebSocket<UnixStream>,
    publisher: goal_source::Publisher,
    instance: String,
    request: u64,
    sequence: u64,
    received: Vec<Value>,
    deadline: Instant,
    remaining: usize,
}

impl Client {
    fn open(endpoint: &Path, executable: &Path, deadline: Instant) -> Result<Self> {
        let (stream, publisher) =
            goal_source::connect_publisher(endpoint, deadline).map_err(|_| CanaryError)?;
        let profile = publisher.execution_profile().ok_or(CanaryError)?;
        if !publisher.matches_executable(executable) {
            return Err(CanaryError);
        }
        let instance = format!(
            "{}:capture:{}",
            publisher
                .instance("native-events")
                .map_err(|_| CanaryError)?,
            uuid::Uuid::now_v7()
        );
        let config = WebSocketConfig::default()
            .max_message_size(Some(1 << 20))
            .max_frame_size(Some(1 << 20));
        let (socket, _) =
            client_with_config("ws://localhost/", stream, Some(config)).map_err(|_| CanaryError)?;
        Ok(Self {
            profile,
            socket,
            publisher,
            instance,
            request: 0,
            sequence: 0,
            received: vec![],
            deadline,
            remaining: 8 << 20,
        })
    }

    fn initialize(&mut self, capture: &mut Capture) -> Result<()> {
        self.call(
            "initialize",
            json!({"clientInfo":{"name":"evertrace-source-canary","version":"1"},
            "capabilities":{"experimentalApi":true}}),
            capture,
        )?;
        self.send(json!({"method":"initialized","params":{}}))
    }

    fn send(&mut self, value: Value) -> Result<()> {
        self.publisher.revalidate().map_err(|_| CanaryError)?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(CanaryError)?;
        self.socket
            .get_mut()
            .set_write_timeout(Some(remaining))
            .map_err(|_| CanaryError)?;
        self.socket
            .send(Message::text(value.to_string()))
            .map_err(|_| CanaryError)
    }

    fn read(&mut self, capture: &mut Capture) -> Result<Value> {
        loop {
            self.publisher.revalidate().map_err(|_| CanaryError)?;
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(CanaryError)?;
            self.socket
                .get_mut()
                .set_read_timeout(Some(remaining))
                .map_err(|_| CanaryError)?;
            let message = self.socket.read().map_err(|_| CanaryError)?;
            let Message::Text(text) = message else {
                if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                    continue;
                }
                return Err(CanaryError);
            };
            self.remaining = self.remaining.checked_sub(text.len()).ok_or(CanaryError)?;
            let value: Value = serde_json::from_str(&text).map_err(|_| CanaryError)?;
            if value.get("method").and_then(Value::as_str) == Some("item/commandExecution/attempt")
            {
                let event = super::Event::decode(text.as_bytes()).ok_or(CanaryError)?;
                if event.params.origin != "user_shell" || !super::uuid(&event.params.call_id) {
                    return Err(CanaryError);
                }
                let input = super::input_revision(
                    &text,
                    &self.instance,
                    self.sequence,
                    &capture.manifest,
                    self.profile.revision(),
                )
                .ok_or(CanaryError)?;
                let observation = host_events::execution_observation(
                    &text,
                    &self.instance,
                    self.sequence,
                    &capture.manifest,
                    self.profile.revision(),
                )
                .ok_or(CanaryError)?;
                let outcome = capture
                    .runtime
                    .capture_host_event(observation)
                    .map_err(|_| CanaryError)?;
                let CaptureOutcome::Durable { cas_digest, .. } = outcome else {
                    return Err(CanaryError);
                };
                let digest: CasDigest = cas_digest.parse().map_err(|_| CanaryError)?;
                let (protected, _) = capture
                    .cas
                    .read_bounded(&digest, 1 << 20, 1 << 20)
                    .map_err(|_| CanaryError)?;
                let correlation =
                    super::protected_correlation(&input, &protected).ok_or(CanaryError)?;
                if capture.facts.measurements.len() >= 16 {
                    return Err(CanaryError);
                }
                capture
                    .facts
                    .measurements
                    .push((input.source_ref, correlation));
                if capture.facts.protected_digest.is_empty() {
                    capture.facts.protected_digest = cas_digest;
                }
                // Exercise the actual decoder, not an independent copy of its rules.
                let mut missing = value.clone();
                missing["params"]
                    .as_object_mut()
                    .ok_or(CanaryError)?
                    .remove("executionOrdinal");
                capture.facts.missing_field_rejected &=
                    super::Event::decode(&serde_json::to_vec(&missing).map_err(|_| CanaryError)?)
                        .is_none();
                let marker = format!("\"threadId\":\"{}\"", event.params.thread_id);
                let conflict = text.replacen(
                    &marker,
                    &format!("{marker},\"threadId\":\"{}\"", uuid::Uuid::now_v7()),
                    1,
                );
                capture.facts.field_conflict_rejected &= conflict.as_str() != text.as_str()
                    && super::Event::decode(conflict.as_bytes()).is_none();
                self.received.push(value.clone());
                self.sequence = self.sequence.checked_add(1).ok_or(CanaryError)?;
            }
            return Ok(value);
        }
    }

    fn call(&mut self, method: &str, params: Value, capture: &mut Capture) -> Result<Value> {
        self.request = self.request.checked_add(1).ok_or(CanaryError)?;
        self.send(json!({"id":self.request,"method":method,"params":params}))?;
        loop {
            let value = self.read(capture)?;
            if value.get("id").and_then(Value::as_u64) == Some(self.request) {
                return value.get("result").cloned().ok_or(CanaryError);
            }
        }
    }

    fn pair(&mut self, count: usize, capture: &mut Capture) -> Result<()> {
        while self.received.len() < count {
            self.read(capture)?;
        }
        if self.received.len() != count {
            return Err(CanaryError);
        }
        let pair = &self.received[count - 2..];
        let before = &pair[0]["params"];
        let after = &pair[1]["params"];
        for field in [
            "threadId",
            "turnId",
            "callId",
            "executionOrdinal",
            "processPid",
            "processStartTicks",
            "executionContextId",
            "workingDirectory",
        ] {
            if before[field] != after[field] {
                return Err(CanaryError);
            }
        }
        if self.profile == super::Profile::Context
            && after["laneSequence"]
                .as_u64()
                .zip(before["laneSequence"].as_u64())
                .is_none_or(|(after, before)| after <= before)
        {
            return Err(CanaryError);
        }
        if before["phase"] != "started"
            || after["phase"] != "exited"
            || after["exitCode"] != 0
            || before["processPid"].as_u64().is_none_or(|value| value == 0)
            || before["processStartTicks"]
                .as_u64()
                .is_none_or(|value| value == 0)
        {
            return Err(CanaryError);
        }
        Ok(())
    }

    fn shell(&mut self, thread: &str, capture: &mut Capture) -> Result<()> {
        let count = self.received.len() + 2;
        self.call(
            "thread/shellCommand",
            json!({"threadId":thread,
            "command":"printf 'evertrace-source-canary\\n'", "timeoutMs":2000}),
            capture,
        )?;
        self.pair(count, capture)?;
        if self.received[count - 2]["params"]["threadId"] != thread {
            return Err(CanaryError);
        }
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.socket.get_mut().shutdown(Shutdown::Both);
    }
}

/// Caller supplies an owned empty working directory; all mutations are confined to probe-owned threads.
/// No host/model is started and no runtime capability is enabled by this collection.
pub fn collect(
    snapshot: RuntimeSnapshot,
    endpoint: &Path,
    executable: &Path,
    directory: &Path,
    manifests: &[(super::Profile, String)],
    deadline: Instant,
) -> Result<CanaryFacts> {
    crate::ConfinedRoot::open_owned_private(directory).map_err(|_| CanaryError)?;
    if fs::read_dir(directory)
        .map_err(|_| CanaryError)?
        .next()
        .is_some()
    {
        return Err(CanaryError);
    }
    let work_deadline = deadline
        .checked_sub(Duration::from_secs(2))
        .ok_or(CanaryError)?;
    let cas = CasStore::open_existing(&snapshot.cas_dir).map_err(|_| CanaryError)?;
    let runtime = CaptureRuntime::open_for_admission(snapshot).map_err(|_| CanaryError)?;
    let mut first = Client::open(endpoint, executable, work_deadline)?;
    let profile = first.profile;
    let (_, manifest) = manifests
        .iter()
        .find(|(value, _)| *value == profile)
        .ok_or(CanaryError)?;
    let facts = CanaryFacts {
        profile,
        measurements: vec![],
        protected_digest: String::new(),
        fork_isolated: false,
        resume_isolated: false,
        replay_deduplicated: false,
        nonidentity_similarity_not_merged: false,
        missing_field_rejected: true,
        field_conflict_rejected: true,
        _verified: (),
    };
    let mut capture = Capture {
        runtime,
        cas,
        manifest: manifest.clone(),
        facts,
    };
    first.initialize(&mut capture)?;
    let mut second = None;
    let mut owned_threads = vec![];
    let outcome = (|| {
        let created = first.call(
            "thread/start",
            json!({"approvalPolicy":"never","sandbox":"read-only","cwd":directory}),
            &mut capture,
        )?;
        let parent = created
            .pointer("/thread/id")
            .and_then(Value::as_str)
            .filter(|id| super::uuid(id))
            .ok_or(CanaryError)?;
        owned_threads.push(parent.to_owned());
        first.shell(parent, &mut capture)?;
        second = Some(Client::open(endpoint, executable, work_deadline)?);
        let other = second.as_mut().ok_or(CanaryError)?;
        if other.profile != profile {
            return Err(CanaryError);
        }
        other.initialize(&mut capture)?;
        let resumed = other.call(
            "thread/resume",
            json!({"threadId":parent,"excludeTurns":true}),
            &mut capture,
        )?;
        if resumed.pointer("/thread/id").and_then(Value::as_str) != Some(parent)
            || !other.received.is_empty()
        {
            return Err(CanaryError);
        }
        first.shell(parent, &mut capture)?;
        other.pair(2, &mut capture)?;
        capture.facts.replay_deduplicated = first.received[2..4] == other.received;
        let forked = first.call(
            "thread/fork",
            json!({"threadId":parent,"excludeTurns":true}),
            &mut capture,
        )?;
        let child = forked
            .pointer("/thread/id")
            .and_then(Value::as_str)
            .filter(|id| super::uuid(id))
            .ok_or(CanaryError)?;
        if child == parent {
            return Err(CanaryError);
        }
        owned_threads.push(child.to_owned());
        first.shell(child, &mut capture)?;
        for client in [&mut first, other] {
            client.call(
                "thread/unsubscribe",
                json!({"threadId":parent}),
                &mut capture,
            )?;
        }
        first.call("thread/archive", json!({"threadId":parent}), &mut capture)?;
        let loaded = first.call("thread/loaded/list", json!({"limit":128}), &mut capture)?;
        if loaded["nextCursor"] != Value::Null
            || loaded["data"]
                .as_array()
                .ok_or(CanaryError)?
                .iter()
                .any(|id| id == parent)
        {
            return Err(CanaryError);
        }
        first.call("thread/unarchive", json!({"threadId":parent}), &mut capture)?;
        let resumed = first.call(
            "thread/resume",
            json!({"threadId":parent,"excludeTurns":true}),
            &mut capture,
        )?;
        if resumed.pointer("/thread/id").and_then(Value::as_str) != Some(parent)
            || first.received.len() != 6
        {
            return Err(CanaryError);
        }
        first.shell(parent, &mut capture)?;
        let starts = [0, 2, 4, 6].map(|index| &first.received[index]["params"]);
        capture.facts.fork_isolated =
            starts[2]["threadId"] == child && starts[0]["threadId"] == parent;
        capture.facts.resume_isolated = starts[3]["threadId"] == parent
            && starts[..3]
                .iter()
                .all(|value| value["turnId"] != starts[3]["turnId"]);
        if profile == super::Profile::Context {
            capture.facts.fork_isolated &=
                starts[0]["executionContextId"] != starts[2]["executionContextId"];
            capture.facts.resume_isolated &= starts[0]["executionContextId"]
                == starts[1]["executionContextId"]
                && starts[0]["executionContextId"] != starts[3]["executionContextId"]
                && starts[3]["laneSequence"] == 1;
            if starts
                .iter()
                .any(|event| event["workingDirectory"] != directory.to_str().unwrap_or(""))
            {
                return Err(CanaryError);
            }
        }
        capture.facts.nonidentity_similarity_not_merged = starts[0]["executionOrdinal"]
            != starts[1]["executionOrdinal"]
            && starts[0]["turnId"] != starts[1]["turnId"];
        Ok(())
    })();
    // Reserve cleanup time even when a source response or measurement fails.
    first.deadline = deadline;
    let mut cleaned = true;
    for thread in &owned_threads {
        cleaned &= first
            .call("thread/archive", json!({"threadId":thread}), &mut capture)
            .is_ok();
    }
    if !cleaned {
        return Err(CanaryError);
    }
    outcome?;
    Ok(capture.facts)
}
