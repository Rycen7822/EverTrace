#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{
    env,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, RecallCueGateMode, RecoveryGateMode,
    RecoveryPreflightCandidate, RuntimeSnapshot,
};
use evertrace_codex::{
    binding::{
        BINDING_PROTOCOL_REVISION, CanonicalBindingCall, NativeHookSpecificOutput,
        NativePermissionDecision, NativePreToolUseOutput, NativeToolUse, NativeToolUseEvent,
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
    request_mcp_binding_sync, request_recall_cue_sync, request_recovery_barrier_sync,
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(2);
// Covers the validated 120s Recovery ceiling plus bounded child setup/cleanup.
const LAUNCHER_CHILD_TIMEOUT: Duration = Duration::from_secs(122);
const RECOVERY_CLEANUP_RESERVE: Duration = Duration::from_millis(25);
const RECALL_CUE_CONTEXT: &[u8] = b"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"additionalContext\":\"EverTrace recall is due. Call evertrace with action=search and input=@due before continuing.\"}}";

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

fn freeze_native_namespace(
    call: &evertrace_domain::evidence::SourceLocalNativeCall,
    deadline: Instant,
) -> Option<evertrace_domain::evidence::SourceLocalNamespaceWitness> {
    use evertrace_capture::{ConfinedReadError, ConfinedReadLimits, ConfinedRoot};
    use evertrace_codex::session_import::{
        MAX_RECORD_BYTES, namespace_from_header, native_session_path,
    };
    let (root, relative) = native_session_path(call.transcript_path.as_deref()?).ok()?;
    let root = ConfinedRoot::open_external_source(&root).ok()?;
    let identity = match root.read(
        &relative,
        ConfinedReadLimits {
            single_file_remaining: 0,
            untracked_total_remaining: 0,
            bundle_remaining: 0,
            deadline,
        },
    ) {
        Ok(file) => file.identity,
        Err(ConfinedReadError::LimitExceeded { metadata, .. }) => metadata.identity,
        Err(_) => return None,
    };
    let mut remaining = MAX_RECORD_BYTES + 1;
    let bytes = root
        .read_first_record(
            &relative,
            identity,
            MAX_RECORD_BYTES,
            &mut remaining,
            deadline,
        )
        .ok()?;
    namespace_from_header(call, &bytes, identity.device, identity.inode, identity.size).ok()
}

fn capture(snapshot_path: &Path, input: CaptureHookInput, started: Instant) -> Result<(), ()> {
    let snapshot = RuntimeSnapshot::load(snapshot_path).map_err(|_| ())?;
    // External metadata is frozen before opening/locking the capture spool.
    let source_local_evidence = input.native_source_call().map(|mut call| {
        call.namespace_witness =
            freeze_native_namespace(&call, started + Duration::from_millis(50));
        evertrace_domain::evidence::SourceLocalEvidence::NativeCall(call)
    });
    let mut runtime = CaptureRuntime::open_for_admission(snapshot.clone()).map_err(|_| ())?;
    let cue_session_id = input.session_id.clone();
    let cue_adapter_manifest_ref = input.adapter_manifest_ref.clone();
    let cue_host_lane_key = input
        .lifecycle
        .as_ref()
        .map(|lifecycle| lifecycle.host_lane_key.clone());
    let cue_boundary = input.event_kind == HookEventKind::PreToolUse;
    let preflight = recovery_preflight(&snapshot, &input);
    let gate = snapshot.recovery_gate;
    let socket = snapshot.recovery_socket_path.clone();
    let configured_timeout =
        Duration::from_millis(u64::from(snapshot.recovery_preflight_timeout_ms));
    let record = CaptureRecordInput {
        source_local_evidence,
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
            HookEventKind::PreToolUse | HookEventKind::PostToolUse | HookEventKind::InputSubmitted
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
        if barrier_failed && let Ok(runtime) = CaptureRuntime::open_for_admission(snapshot.clone())
        {
            let _ = runtime.record_recovery_unavailable(&recovery_gap_record);
        }
    }
    if let Some(cue) = select_recall_cue(
        &snapshot,
        &cue_session_id,
        cue_host_lane_key.as_deref(),
        &cue_adapter_manifest_ref,
        cue_boundary,
    ) {
        let remaining = Duration::from_millis(250).saturating_sub(started.elapsed());
        if remaining >= Duration::from_millis(1) {
            let _ = request_recall_cue_sync(
                &snapshot.recovery_socket_path,
                env!("CARGO_PKG_VERSION"),
                cue,
                remaining,
                |_| emit_recall_context(io::stdout().lock()),
            );
        }
    }
    Ok(())
}

fn select_recall_cue(
    snapshot: &RuntimeSnapshot,
    session_id: &str,
    host_lane_key: Option<&str>,
    adapter_manifest_id: &str,
    cue_boundary: bool,
) -> Option<evertrace_domain::recall::RecallCueSnapshot> {
    if snapshot.recall_cue_gate != RecallCueGateMode::Active
        || !cue_boundary
        || snapshot.recall_cue_adapter_manifest_id.as_deref() != Some(adapter_manifest_id)
    {
        return None;
    }
    let host_lane_key = host_lane_key?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())?;
    let mut matches = snapshot.recall_cues.iter().filter(|cue| {
        cue.session_id == session_id
            && cue.host_lane_key == host_lane_key
            && cue.adapter_manifest_id == adapter_manifest_id
            && cue.runtime_generation == snapshot.generation
            && cue.expires_at_us > now
    });
    let cue = matches.next()?.clone();
    matches.next().is_none().then_some(cue)
}

#[cfg(test)]
fn recall_cue_enabled(
    gate: RecallCueGateMode,
    configured_manifest: Option<&str>,
    input_manifest: &str,
    cue_boundary: bool,
) -> bool {
    gate == RecallCueGateMode::Active && cue_boundary && configured_manifest == Some(input_manifest)
}

fn emit_recall_context(
    mut output: impl Write,
) -> evertrace_domain::recall::PresentationAttemptState {
    use evertrace_domain::recall::PresentationAttemptState;

    let mut written = 0;
    while written < RECALL_CUE_CONTEXT.len() {
        match output.write(&RECALL_CUE_CONTEXT[written..]) {
            Ok(0) | Err(_) if written == 0 => return PresentationAttemptState::FailedPreEmit,
            Ok(0) | Err(_) => return PresentationAttemptState::PresentationUnknown,
            Ok(count) => written += count,
        }
    }
    if output.flush().is_err() {
        PresentationAttemptState::PresentationUnknown
    } else {
        PresentationAttemptState::Emitted
    }
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
    let mut native = NativeToolUse::<McpToolInput>::from_json(bytes).map_err(|_| ())?;
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
            transcript_path: native.transcript_path,
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
            hook_event_name: NativeToolUseEvent::PreToolUse,
            permission_decision: NativePermissionDecision::Allow,
            updated_input: native.tool_input,
        },
    };
    io::stdout()
        .write_all(&output.to_json().map_err(|_| ())?)
        .map_err(|_| ())
}

struct InvocationChild {
    child: Option<std::process::Child>,
    snapshot: evertrace_capture::InvocationSnapshot,
}

impl Drop for InvocationChild {
    fn drop(&mut self) {
        let reaped = if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            child.wait().is_ok()
        } else {
            true
        };
        if reaped {
            let _ = self.snapshot.remove();
        }
    }
}

fn launch(root: &Path, bytes: &[u8], started: Instant) -> Result<(), ()> {
    let capture_input = CaptureHookInput::from_json(bytes).ok();
    let native_input = NativeToolUse::from_json(bytes).ok();
    let submission = evertrace_codex::binding::NativeInputSubmission::from_json(bytes).ok();
    let (session_id, binding_mode) = match (&capture_input, &native_input, &submission) {
        (Some(input), None, None) => (input.session_id.as_str(), false),
        (None, None, Some(input)) => (input.session_id.as_str(), false),
        (None, Some(input), None) => (
            input.session_id.as_str(),
            input.hook_event_name == NativeToolUseEvent::PreToolUse && input.targets_evertrace(),
        ),
        _ => return Err(()),
    };
    let launcher = StableLauncher::open(root).map_err(|_| ())?;
    let generation = launcher.resolve_for_session(session_id).map_err(|_| ())?;
    evertrace_capture::CasStore::open(root.join("cas")).map_err(|_| ())?;
    let fence = evertrace_capture::MaintenanceFence::open(root).map_err(|_| ())?;
    if let Ok(exclusive) = fence.exclusive() {
        evertrace_capture::InvocationSnapshot::clean_interrupted(root, &exclusive)
            .map_err(|_| ())?;
    }
    let guard = loop {
        match fence.shared() {
            Ok(guard) => break guard,
            Err(evertrace_capture::CasError::LockBusy)
                if started.elapsed() < Duration::from_secs(1) =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(()),
        }
    };
    let invocation =
        evertrace_capture::InvocationSnapshot::prepare(root, &generation.runtime_snapshot, &guard)
            .map_err(|_| ())?;
    let mut running = InvocationChild {
        child: None,
        snapshot: invocation,
    };
    let normalized;
    let bytes = if !binding_mode && let Some(native) = native_input {
        normalized = CaptureHookInput::from_native(native, generation.generation)
            .map_err(|_| ())?
            .to_json()
            .map_err(|_| ())?;
        normalized.as_slice()
    } else if let Some(submission) = submission {
        normalized = CaptureHookInput::from_submission(submission, generation.generation)
            .map_err(|_| ())?
            .to_json()
            .map_err(|_| ())?;
        normalized.as_slice()
    } else {
        bytes
    };
    let child_timeout = LAUNCHER_CHILD_TIMEOUT;
    let deadline = started.checked_add(child_timeout).ok_or(())?;
    if Instant::now() >= deadline {
        return Err(());
    }
    // The launcher has not started its stdin writer thread yet. Only this
    // spawn inherits the duplicate of the parent's shared flock description.
    let inherited = guard.inherit_shared_for_spawn().map_err(|_| ())?;
    let child = Command::new(generation.executable)
        .arg(if binding_mode {
            "--binding-runtime-snapshot"
        } else {
            "--runtime-snapshot"
        })
        .arg(running.snapshot.path())
        .stdin(Stdio::piped())
        .stdout(if binding_mode {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    drop(inherited);
    running.child = Some(child);
    let child = running.child.as_mut().ok_or(())?;
    let mut child_stdin = child.stdin.take().ok_or(())?;
    let input = bytes.to_vec();
    let writer = thread::spawn(move || child_stdin.write_all(&input));
    loop {
        if child.try_wait().map_err(|_| ())?.is_some() {
            running.child = None;
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
        HookEventKind::InputSubmitted => ObservationRole::Message,
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
        HookEventKind::InputSubmitted
        | HookEventKind::SubagentStart
        | HookEventKind::SubagentTerminal
        | HookEventKind::Compact
        | HookEventKind::SourceClose
        | HookEventKind::ParentSessionEnd
        | HookEventKind::LivenessProbe => SourceRole::Host,
    }
}

const fn unsupported_classification(
    kind: HookEventKind,
    payload_length: usize,
) -> Option<UnsupportedRecordClassification> {
    if !matches!(kind, HookEventKind::InputSubmitted)
        && payload_length > evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES
    {
        Some(UnsupportedRecordClassification::UnboundedToolOutput)
    } else {
        None
    }
}

#[cfg(test)]
mod budget_proof {
    use super::*;

    struct ProbeWriter {
        first_write: usize,
        fail_flush: bool,
        calls: usize,
    }

    impl Write for ProbeWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                Ok(self.first_write.min(bytes.len()))
            } else {
                Err(io::Error::other("probe"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("probe"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn launcher_and_barrier_budgets_are_bounded_without_sleeping() {
        assert_eq!(LAUNCHER_CHILD_TIMEOUT, Duration::from_secs(122));
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

    #[test]
    fn recall_cue_is_the_fixed_native_additional_context_envelope() {
        let output = std::str::from_utf8(RECALL_CUE_CONTEXT).unwrap();
        assert_eq!(
            output,
            "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"additionalContext\":\"EverTrace recall is due. Call evertrace with action=search and input=@due before continuing.\"}}"
        );
        assert!(!output.contains("recall_need"));
        assert!(recall_cue_enabled(
            RecallCueGateMode::Active,
            Some("manifest:a"),
            "manifest:a",
            true,
        ));
        assert!(!recall_cue_enabled(
            RecallCueGateMode::Active,
            Some("manifest:a"),
            "manifest:b",
            true,
        ));
        assert!(!recall_cue_enabled(
            RecallCueGateMode::Disabled,
            Some("manifest:a"),
            "manifest:a",
            true,
        ));
        let mut snapshot = RuntimeSnapshot::for_data_dir(
            Path::new("/tmp/evertrace-hook-cue-test"),
            3,
            evertrace_capture::SpoolLimits {
                high_watermark_bytes: 1024,
                low_watermark_bytes: 512,
                max_main_files: 4,
                emergency_slots: 2,
            },
            evertrace_capture::RecoverySnapshotSettings {
                gate: RecoveryGateMode::Disabled,
                preflight_timeout_ms: 100,
                effective_config_hash: [7; 32],
                adapter_manifest_id: None,
                classifier_revision: 1,
                max_bundle_bytes: 4096,
                max_untracked_file_bytes: 1024,
                max_untracked_total_bytes: 2048,
                recall_cue_gate: RecallCueGateMode::Active,
                recall_cue_adapter_manifest_id: Some("manifest:a".into()),
            },
        )
        .unwrap();
        snapshot.recall_cues.push(
            evertrace_domain::recall::RecallCueSnapshot {
                session_id: "session:a".into(),
                execution_lane_id: evertrace_domain::ids::ExecutionLaneId::new_v7(),
                host_lane_key: "lane:a".into(),
                adapter_manifest_id: "manifest:a".into(),
                runtime_generation: 3,
                recall_need_hash: [8; 32],
                presentation_attempt_id: evertrace_domain::ids::PresentationAttemptId::new_v7(),
                expires_at_us: i64::MAX,
                checksum: [0; 32],
            }
            .seal()
            .unwrap(),
        );
        assert!(
            select_recall_cue(&snapshot, "session:a", Some("lane:a"), "manifest:a", true).is_some()
        );
        assert!(
            select_recall_cue(&snapshot, "session:b", Some("lane:a"), "manifest:a", true).is_none()
        );
        assert!(
            select_recall_cue(&snapshot, "session:a", Some("lane:b"), "manifest:a", true).is_none()
        );
        assert_eq!(
            emit_recall_context(ProbeWriter {
                first_write: 0,
                fail_flush: false,
                calls: 0,
            }),
            evertrace_domain::recall::PresentationAttemptState::FailedPreEmit
        );
        assert_eq!(
            emit_recall_context(ProbeWriter {
                first_write: 1,
                fail_flush: false,
                calls: 0,
            }),
            evertrace_domain::recall::PresentationAttemptState::PresentationUnknown
        );
        assert_eq!(
            emit_recall_context(ProbeWriter {
                first_write: RECALL_CUE_CONTEXT.len(),
                fail_flush: true,
                calls: 0,
            }),
            evertrace_domain::recall::PresentationAttemptState::PresentationUnknown
        );
    }
}
