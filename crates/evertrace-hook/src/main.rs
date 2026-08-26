#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{
    env,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use evertrace_capture::{CaptureRecordInput, CaptureRuntime, RuntimeSnapshot};
use evertrace_codex::{
    hook_input::{CaptureHookInput, HookEventKind, MAX_CAPTURE_HOOK_INPUT},
    install::StableLauncher,
};
use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, IdentityStrength, ObservationRole, SourceRole,
    UnsupportedRecordClassification,
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(2);

fn main() {
    let _ = run();
}

fn run() -> Result<(), ()> {
    let mut arguments = env::args_os().skip(1);
    let mode = arguments.next().ok_or(())?;
    let path = arguments.next().ok_or(())?;
    if arguments.next().is_some() {
        return Err(());
    }
    let bytes = read_input()?;
    let input = CaptureHookInput::from_json(&bytes).map_err(|_| ())?;
    match mode.to_str() {
        Some("--runtime-snapshot") => capture(Path::new(&path), input),
        Some("--launcher-root") => launch(Path::new(&path), &bytes, &input),
        _ => Err(()),
    }
}

fn read_input() -> Result<Vec<u8>, ()> {
    let limit = u64::try_from(MAX_CAPTURE_HOOK_INPUT)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(())?;
    let mut bytes = Vec::new();
    io::stdin()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_CAPTURE_HOOK_INPUT {
        return Err(());
    }
    Ok(bytes)
}

fn capture(snapshot_path: &Path, input: CaptureHookInput) -> Result<(), ()> {
    let snapshot = RuntimeSnapshot::load(snapshot_path).map_err(|_| ())?;
    let mut runtime = CaptureRuntime::open(snapshot).map_err(|_| ())?;
    runtime
        .capture(CaptureRecordInput {
            spool_record_id: input.spool_record_id,
            source_observation_id_hint: input.source_observation_id_hint,
            source_instance_id: input.source_instance_id,
            source_revision: input.source_revision,
            source_record_identity: input.source_record_identity,
            identity_strength: input.identity_strength,
            source_kind: input.source_kind,
            identity_domain: input.identity_domain,
            source_ref: input.source_ref,
            session_ref: input.session_id,
            turn_ref: input.turn_id,
            tool_ref: input.tool_use_id,
            source_sequence: input.source_sequence,
            task_id: input.task_id,
            repository_instance_id: input.repository_instance_id,
            worktree_instance_id: input.worktree_instance_id,
            source_byte_range: None,
            source_revision_mode: input.source_revision_mode,
            previous_source_revision: input.previous_source_revision,
            close_watermark: (input.event_kind == HookEventKind::SourceClose)
                .then_some(input.source_sequence),
            observation_role: observation_role(input.event_kind),
            correlation: input.correlation,
            scope_effect_claims: input.scope_effect_claims,
            unsupported_record_classification: unsupported_classification(
                input.event_kind,
                input.payload.len(),
            ),
            source_role: source_role(input.event_kind),
            content_trust: ContentTrust::Observed,
            capture_completeness: if matches!(
                input.identity_strength,
                Some(IdentityStrength::StableNative | IdentityStrength::StableSourceSequence)
            ) {
                CaptureCompleteness::Complete
            } else {
                CaptureCompleteness::Partial
            },
            surface_eligible: matches!(
                input.event_kind,
                HookEventKind::PreToolUse | HookEventKind::PostToolUse
            ) && input.payload.len()
                <= evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES,
            adapter_revision: 1,
            adapter_manifest_ref: input.adapter_manifest_ref,
            eligible_event_manifest_ref: input.eligible_event_manifest_ref,
            parser_revision: 1,
            canonicalization_revision: 1,
            event_time_us: input.event_time_us,
            raw_payload: input.payload.into_bytes(),
        })
        .map(|_| ())
        .map_err(|_| ())
}

fn launch(root: &Path, bytes: &[u8], input: &CaptureHookInput) -> Result<(), ()> {
    let launcher = StableLauncher::open(root).map_err(|_| ())?;
    let generation = launcher
        .resolve_for_session(&input.session_id)
        .map_err(|_| ())?;
    let mut child = Command::new(generation.executable)
        .arg("--runtime-snapshot")
        .arg(generation.runtime_snapshot)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let mut child_stdin = child.stdin.take().ok_or(())?;
    let input = bytes.to_vec();
    let writer = thread::spawn(move || child_stdin.write_all(&input));
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if child.try_wait().map_err(|_| ())?.is_some() {
            return writer.join().map_err(|_| ())?.map_err(|_| ());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            return Err(());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

const fn observation_role(kind: HookEventKind) -> ObservationRole {
    match kind {
        HookEventKind::PreToolUse => ObservationRole::Intent,
        HookEventKind::PostToolUse => ObservationRole::Result,
        HookEventKind::SubagentStart
        | HookEventKind::SubagentTerminal
        | HookEventKind::Compact
        | HookEventKind::SourceClose => ObservationRole::Lifecycle,
    }
}

const fn source_role(kind: HookEventKind) -> SourceRole {
    match kind {
        HookEventKind::PreToolUse | HookEventKind::PostToolUse => SourceRole::Tool,
        HookEventKind::SubagentStart
        | HookEventKind::SubagentTerminal
        | HookEventKind::Compact
        | HookEventKind::SourceClose => SourceRole::Host,
    }
}

const fn unsupported_classification(
    kind: HookEventKind,
    payload_length: usize,
) -> Option<UnsupportedRecordClassification> {
    if payload_length > evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES {
        Some(UnsupportedRecordClassification::UnboundedToolOutput)
    } else if matches!(
        kind,
        HookEventKind::SubagentStart
            | HookEventKind::SubagentTerminal
            | HookEventKind::Compact
            | HookEventKind::SourceClose
    ) {
        Some(UnsupportedRecordClassification::UnknownRecordType)
    } else {
        None
    }
}
