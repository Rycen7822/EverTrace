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

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, RecoveryGateMode,
    RecoveryPreflightCandidate, RuntimeSnapshot,
};
use evertrace_codex::{
    binding::{
        BINDING_PROTOCOL_REVISION, CanonicalBindingCall, NativeHookSpecificOutput,
        NativePermissionDecision, NativePreToolUse, NativePreToolUseEvent, NativePreToolUseOutput,
        PublicWorkspace, validated_bound_workspace,
    },
    hook_input::{CaptureHookInput, HookEventKind, MAX_CAPTURE_HOOK_INPUT},
    install::StableLauncher,
    recovery::classify_codex_pretool_candidate,
};
use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, IdentityStrength, ObservationRole, SourceRole,
    UnsupportedRecordClassification,
};
use evertrace_domain::{
    ids::{CommandId, RecoveryCaptureRequestId},
    repository::DestructiveDetectionStatus,
    revision::RevisionId,
};
use evertrace_protocol::{
    command::{McpBindingIssueCommand, RecoveryBarrierLocator},
    mcp::McpToolInput,
    request_mcp_binding_sync, request_recovery_barrier_sync,
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(2);
const RECOVERY_CLEANUP_RESERVE: Duration = Duration::from_millis(25);

fn main() {
    let _ = run();
}

fn run() -> Result<(), ()> {
    let started = Instant::now();
    let mut arguments = env::args_os().skip(1);
    let mode = arguments.next().ok_or(())?;
    let path = arguments.next().ok_or(())?;
    if arguments.next().is_some() {
        return Err(());
    }
    let bytes = read_input()?;
    match mode.to_str() {
        Some("--runtime-snapshot") => capture(
            Path::new(&path),
            CaptureHookInput::from_json(&bytes).map_err(|_| ())?,
            started,
        ),
        Some("--binding-runtime-snapshot") => binding_rewrite(Path::new(&path), &bytes),
        Some("--launcher-root") => launch(Path::new(&path), &bytes, started),
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

fn capture(snapshot_path: &Path, input: CaptureHookInput, started: Instant) -> Result<(), ()> {
    let snapshot = RuntimeSnapshot::load(snapshot_path).map_err(|_| ())?;
    let preflight = recovery_preflight(&snapshot, &input);
    let gate = snapshot.recovery_gate;
    let socket = snapshot.recovery_socket_path.clone();
    let configured_timeout =
        Duration::from_millis(u64::from(snapshot.recovery_preflight_timeout_ms));
    let mut runtime = CaptureRuntime::open(snapshot.clone()).map_err(|_| ())?;
    let record = CaptureRecordInput {
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
        source_sequence_origin: input.source_sequence_origin,
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
        lifecycle: input.lifecycle,
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
    };
    let recovery_gap_record = record.clone();
    let outcome = match preflight {
        Some(intent) => runtime.capture_with_recovery_preflight(record, intent),
        None => runtime.capture(record),
    }
    .map_err(|_| ())?;
    drop(runtime);
    if gate == RecoveryGateMode::Active
        && let CaptureOutcome::Durable {
            spool_record_id,
            recovery_preflight: Some(pending),
            ..
        } = outcome
    {
        let remaining = recovery_barrier_budget(
            configured_timeout,
            started.elapsed(),
            RECOVERY_CLEANUP_RESERVE,
        );
        let barrier_failed = remaining.is_none_or(|timeout| {
            request_recovery_barrier_sync(
                &socket,
                env!("CARGO_PKG_VERSION"),
                RecoveryBarrierLocator {
                    spool_record_id: spool_record_id.clone(),
                    recovery_capture_request_id: pending.request_id,
                    pending_revision_id: pending.pending_revision_id,
                },
                timeout,
            )
            .is_err()
        });
        if barrier_failed && let Ok(runtime) = CaptureRuntime::open(snapshot) {
            let _ = runtime.record_recovery_unavailable(&recovery_gap_record);
        }
    }
    Ok(())
}

fn recovery_preflight(
    snapshot: &RuntimeSnapshot,
    input: &CaptureHookInput,
) -> Option<RecoveryPreflightCandidate> {
    if !recovery_candidate_matches(snapshot, input) {
        return None;
    }
    let cwd = env::current_dir().ok()?;
    Some(RecoveryPreflightCandidate {
        pending_command_id: CommandId::new_v7(),
        recovery_capture_request_id: RecoveryCaptureRequestId::new_v7(),
        pending_revision_id: RevisionId::new_v7(),
        observed_cwd: cwd.to_string_lossy().into_owned(),
        classifier_revision: snapshot.recovery_classifier_revision,
        adapter_manifest_id: input.adapter_manifest_ref.clone(),
    })
}

fn binding_rewrite(snapshot_path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let mut native = NativePreToolUse::<McpToolInput>::from_json(bytes).map_err(|_| ())?;
    native.validate_host_fields().map_err(|_| ())?;
    if !native.targets_evertrace() || !native.tool_input.validate() {
        return Ok(());
    }
    PublicWorkspace::parse(&native.tool_input.workspace).map_err(|_| ())?;
    let original_call = CanonicalBindingCall {
        action: native.tool_input.action.as_str().into(),
        workspace: native.tool_input.workspace.clone(),
        input: native.tool_input.input.clone(),
        refs: native.tool_input.refs.clone(),
    };
    let snapshot = RuntimeSnapshot::load(snapshot_path).map_err(|_| ())?;
    let issued = request_mcp_binding_sync(
        &snapshot.recovery_socket_path,
        env!("CARGO_PKG_VERSION"),
        McpBindingIssueCommand {
            session_id: native.session_id,
            turn_id: native.turn_id,
            tool_use_id: native.tool_use_id,
            agent_id: native.agent_id,
            original_input: native.tool_input.clone(),
            launcher_protocol_revision: BINDING_PROTOCOL_REVISION,
        },
        CHILD_TIMEOUT,
    )
    .map_err(|_| ())?;
    native.tool_input.workspace =
        validated_bound_workspace(&original_call, &issued.bound_workspace).map_err(|_| ())?;
    let output = NativePreToolUseOutput {
        hook_specific_output: NativeHookSpecificOutput {
            hook_event_name: NativePreToolUseEvent::PreToolUse,
            permission_decision: NativePermissionDecision::Allow,
            updated_input: native.tool_input,
        },
    };
    io::stdout()
        .write_all(&output.to_json().map_err(|_| ())?)
        .map_err(|_| ())
}

fn launch(root: &Path, bytes: &[u8], started: Instant) -> Result<(), ()> {
    let capture_input = CaptureHookInput::from_json(bytes).ok();
    let native_input = NativePreToolUse::<McpToolInput>::from_json(bytes).ok();
    let (session_id, binding_mode) = match (&capture_input, &native_input) {
        (Some(input), None) => (input.session_id.as_str(), false),
        (None, Some(input)) => (input.session_id.as_str(), true),
        _ => return Err(()),
    };
    let launcher = StableLauncher::open(root).map_err(|_| ())?;
    let generation = launcher.resolve_for_session(session_id).map_err(|_| ())?;
    let snapshot = RuntimeSnapshot::load(&generation.runtime_snapshot).map_err(|_| ())?;
    let child_timeout = capture_input.as_ref().map_or(CHILD_TIMEOUT, |input| {
        launcher_child_timeout(
            recovery_candidate_matches(&snapshot, input),
            snapshot.recovery_preflight_timeout_ms,
        )
    });
    let deadline = started.checked_add(child_timeout).ok_or(())?;
    if Instant::now() >= deadline {
        return Err(());
    }
    let mut child = Command::new(generation.executable)
        .arg(if binding_mode {
            "--binding-runtime-snapshot"
        } else {
            "--runtime-snapshot"
        })
        .arg(generation.runtime_snapshot)
        .stdin(Stdio::piped())
        .stdout(if binding_mode {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let mut child_stdin = child.stdin.take().ok_or(())?;
    let input = bytes.to_vec();
    let writer = thread::spawn(move || child_stdin.write_all(&input));
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

fn recovery_candidate_matches(snapshot: &RuntimeSnapshot, input: &CaptureHookInput) -> bool {
    if snapshot.recovery_gate != RecoveryGateMode::Active
        || input.event_kind != HookEventKind::PreToolUse
        || snapshot.recovery_adapter_manifest_id.as_deref()
            != Some(input.adapter_manifest_ref.as_str())
        || input.repository_instance_id.is_none()
        || input.worktree_instance_id.is_none()
    {
        return false;
    }
    let Ok(cwd) = env::current_dir() else {
        return false;
    };
    classify_codex_pretool_candidate(&input.payload, &cwd).detection_status
        == DestructiveDetectionStatus::Matched
}

fn launcher_child_timeout(recovery_candidate: bool, configured_timeout_ms: u32) -> Duration {
    if recovery_candidate {
        Duration::from_millis(u64::from(configured_timeout_ms))
    } else {
        CHILD_TIMEOUT
    }
}

fn recovery_barrier_budget(
    configured: Duration,
    elapsed: Duration,
    cleanup_reserve: Duration,
) -> Option<Duration> {
    configured
        .checked_sub(elapsed)?
        .checked_sub(cleanup_reserve)
}

const fn observation_role(kind: HookEventKind) -> ObservationRole {
    match kind {
        HookEventKind::PreToolUse => ObservationRole::Intent,
        HookEventKind::PostToolUse => ObservationRole::Result,
        HookEventKind::SubagentStart
        | HookEventKind::SubagentTerminal
        | HookEventKind::Compact
        | HookEventKind::SourceClose
        | HookEventKind::ParentSessionEnd
        | HookEventKind::LivenessProbe => ObservationRole::Lifecycle,
    }
}

const fn source_role(kind: HookEventKind) -> SourceRole {
    match kind {
        HookEventKind::PreToolUse | HookEventKind::PostToolUse => SourceRole::Tool,
        HookEventKind::SubagentStart
        | HookEventKind::SubagentTerminal
        | HookEventKind::Compact
        | HookEventKind::SourceClose
        | HookEventKind::ParentSessionEnd
        | HookEventKind::LivenessProbe => SourceRole::Host,
    }
}

const fn unsupported_classification(
    _kind: HookEventKind,
    payload_length: usize,
) -> Option<UnsupportedRecordClassification> {
    if payload_length > evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES {
        Some(UnsupportedRecordClassification::UnboundedToolOutput)
    } else {
        None
    }
}

#[cfg(test)]
mod budget_proof {
    use super::*;

    #[test]
    fn launcher_and_barrier_budgets_are_bounded_without_sleeping() {
        assert_eq!(launcher_child_timeout(false, 10_000), CHILD_TIMEOUT);
        assert_eq!(
            launcher_child_timeout(true, 10_000),
            Duration::from_secs(10)
        );
        assert_eq!(
            recovery_barrier_budget(
                Duration::from_secs(10),
                Duration::from_secs(3),
                Duration::from_millis(25),
            ),
            Some(Duration::from_millis(6_975))
        );
        assert_eq!(
            recovery_barrier_budget(
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_millis(25),
            ),
            None
        );
    }
}
