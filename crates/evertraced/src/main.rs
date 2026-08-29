#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{env, fs, path::PathBuf, sync::Arc};

use evertrace_engine::{
    EngineService, HealthDispatchError, McpActionService, McpBindingAuthority, McpBindingIssue,
    McpServiceAction, McpServiceRequest, McpServiceResult, McpServiceStatus, RecallCueOutcome,
    RecallCueService, RecoveryActionOutcome, RecoveryActionService,
    RecoveryBarrierLocator as EngineRecoveryLocator, RecoveryBarrierService, RecoveryError,
    RecoveryRequest, RecoveryUnsupportedReason as EngineUnsupportedReason, RuntimeMode,
    open_writer, publish_recovery_runtime, recall::spawn_recall_worker, spawn_writer,
};
use evertrace_protocol::{
    LocalServer, ServerOptions,
    command::{Command as ProtocolCommand, RecallCueCommand},
    dto::{ClientKind, HealthMode, PROTOCOL_VERSION},
    envelope::{McpItem, McpItems, McpResultEnvelope, McpStatus},
    error::ErrorCode,
    resolve_data_dir,
    response::{
        HealthResponse, McpBindingIssuedResponse, RecallCueResponse, RecoveryActionResponse,
        RecoveryTerminalResponse, RecoveryUnsupportedReason, Response,
    },
};
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("evertraced: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = StartupArgs::parse()?;
    let config_path = config_path(args.config)?;
    let source = fs::read_to_string(config_path)?;
    let mode = if args.maintenance {
        RuntimeMode::Maintenance
    } else {
        RuntimeMode::Normal
    };
    let engine = Arc::new(EngineService::from_toml(&source, mode)?);
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(engine.data_dir(), home.as_deref(), |name| env::var_os(name))?;
    let runtime_snapshot = publish_recovery_runtime(&data_dir, engine.effective_config(), None)?;
    let writer = open_writer(&data_dir).await?;
    let (writer_handle, mut writer_task) = spawn_writer(writer, 64)?;
    let mut recall_worker = spawn_recall_worker(
        writer_handle.clone(),
        runtime_snapshot.clone(),
        data_dir.clone(),
    );
    let mcp_bindings = McpBindingAuthority::from_device_key_dir(&runtime_snapshot.device_key_dir)?;
    let mcp_service = McpActionService::open(
        mcp_bindings.clone(),
        &data_dir,
        writer_handle.clone(),
        runtime_snapshot.clone(),
    )
    .await?;
    let recovery_service =
        RecoveryBarrierService::new(runtime_snapshot.clone(), writer_handle.clone());
    let recall_cue_service = RecallCueService::new(
        writer_handle.clone(),
        runtime_snapshot.recall_cue_gate,
        runtime_snapshot.recall_cue_adapter_manifest_id.clone(),
        runtime_snapshot.generation,
        runtime_snapshot.effective_config_hash,
        &data_dir,
    );
    let recovery_action_service = RecoveryActionService::new(
        runtime_snapshot,
        writer_handle.clone(),
        recovery_service.mutation_fence(),
    );
    recovery_service.reconcile_pending_on_startup().await?;
    recovery_action_service
        .reconcile_pending_on_startup()
        .await?;
    let mut writer_handle = Some(writer_handle);
    let server = match LocalServer::bind(&data_dir, ServerOptions::new(env!("CARGO_PKG_VERSION"))) {
        Ok(server) => server,
        Err(error) => {
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            return Err(error.into());
        }
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handler_engine = Arc::clone(&engine);
    let handler_recovery_action_service = recovery_action_service.clone();
    let handler_mcp_bindings = mcp_bindings;
    let handler_mcp_service = mcp_service;
    let mut task = tokio::spawn(server.run_dispatch_with_context(
        shutdown_rx,
        move |context, request_id, command| {
            let handler_engine = Arc::clone(&handler_engine);
            let recovery_service = recovery_service.clone();
            let recovery_action_service = handler_recovery_action_service.clone();
            let mcp_bindings = handler_mcp_bindings.clone();
            let mcp_service = handler_mcp_service.clone();
            let recall_cue_service = recall_cue_service.clone();
            async move {
                match command {
                    ProtocolCommand::Health => {
                        let snapshot = handler_engine.health().map_err(|error| match error {
                            HealthDispatchError::MaintenanceMode => ErrorCode::MaintenanceMode,
                        })?;
                        Ok(Response::Health(HealthResponse {
                            protocol_version: PROTOCOL_VERSION,
                            mode: HealthMode::Normal,
                            config_version: snapshot.config_version,
                            effective_config_hash: hex(&snapshot.effective_config_hash),
                            algorithm_revision: snapshot.algorithm_revision,
                        }))
                    }
                    ProtocolCommand::RecoveryBarrier(locator) => {
                        let result = recovery_service
                            .handle(EngineRecoveryLocator {
                                spool_record_id: locator.spool_record_id,
                                recovery_capture_request_id: locator.recovery_capture_request_id,
                                pending_revision_id: locator.pending_revision_id,
                            })
                            .await
                            .map_err(map_recovery_error)?;
                        Ok(Response::RecoveryTerminal(RecoveryTerminalResponse {
                            recovery_capture_request_id: result.recovery_capture_request_id,
                            pending_revision_id: result.pending_revision_id,
                            terminal_revision_id: result.terminal_revision_id,
                            status: result.status,
                            recovery_bundle_id: result.recovery_bundle_id,
                            durable_terminal_proven: true,
                        }))
                    }
                    ProtocolCommand::RequestRecovery(request) => {
                        let result = recovery_action_service
                            .handle(RecoveryRequest {
                                request_id,
                                recovery_bundle_id: request.recovery_bundle_id,
                                target_worktree_instance_id: request.target_worktree_instance_id,
                                application_kind: request.application_kind,
                            })
                            .await
                            .map_err(map_recovery_error)?;
                        let response = match result {
                            RecoveryActionOutcome::Application {
                                recovery_application_id,
                                application_status,
                                replayed,
                            } => RecoveryActionResponse {
                                recovery_application_id: Some(recovery_application_id),
                                application_status: Some(application_status),
                                replayed,
                                unsupported_reason: None,
                            },
                            RecoveryActionOutcome::Unsupported(reason) => RecoveryActionResponse {
                                recovery_application_id: None,
                                application_status: None,
                                replayed: false,
                                unsupported_reason: Some(map_unsupported_reason(reason)),
                            },
                        };
                        Ok(Response::RecoveryAction(response))
                    }
                    ProtocolCommand::IssueMcpBinding(issue) => {
                        if context.client_kind != ClientKind::Hook {
                            return Err(ErrorCode::Untrusted);
                        }
                        let grant = mcp_bindings
                            .issue(McpBindingIssue {
                                session_id: issue.session_id,
                                turn_id: issue.turn_id,
                                tool_use_id: issue.tool_use_id,
                                agent_id: issue.agent_id,
                                action: issue.original_input.action.as_str().into(),
                                workspace: issue.original_input.workspace,
                                input: issue.original_input.input,
                                refs: issue.original_input.refs,
                                launcher_protocol_revision: issue.launcher_protocol_revision,
                            })
                            .map_err(|_| ErrorCode::Untrusted)?;
                        Ok(Response::McpBindingIssued(McpBindingIssuedResponse {
                            bound_workspace: grant.bound_workspace,
                            expires_at_us: grant.expires_at_us,
                        }))
                    }
                    ProtocolCommand::McpCall(call) => {
                        if context.client_kind != ClientKind::Mcp {
                            return Err(ErrorCode::Untrusted);
                        }
                        let action = match call.input.action {
                            evertrace_protocol::mcp::McpAction::Search => McpServiceAction::Search,
                            evertrace_protocol::mcp::McpAction::Get => McpServiceAction::Get,
                            evertrace_protocol::mcp::McpAction::Add => McpServiceAction::Add,
                            evertrace_protocol::mcp::McpAction::Organize => {
                                McpServiceAction::Organize
                            }
                        };
                        let result = mcp_service
                            .handle(
                                &context.connection_id,
                                McpServiceRequest {
                                    request_id,
                                    action,
                                    workspace: call.input.workspace,
                                    input: call.input.input,
                                    refs: call.input.refs,
                                    client_cwd: call.client_cwd,
                                },
                            )
                            .await
                            .map_err(|_| ErrorCode::Internal)?;
                        Ok(Response::McpResult(Box::new(map_mcp_result(result))))
                    }
                    ProtocolCommand::RecallCue(command) => {
                        if context.client_kind != ClientKind::Hook {
                            return Err(ErrorCode::Untrusted);
                        }
                        let outcome = match command {
                            RecallCueCommand::Authorize { snapshot } => {
                                recall_cue_service.authorize(&snapshot).await
                            }
                            RecallCueCommand::Outcome { snapshot, outcome } => {
                                recall_cue_service.outcome(&snapshot, outcome).await
                            }
                        }
                        .map_err(|_| ErrorCode::Untrusted)?;
                        Ok(Response::RecallCue(match outcome {
                            RecallCueOutcome::Authorized => RecallCueResponse::Authorized,
                            RecallCueOutcome::OutcomeAccepted => RecallCueResponse::OutcomeAccepted,
                        }))
                    }
                }
            }
        },
    ));
    tokio::select! {
        result = &mut task => {
            let server_result = result;
            recovery_action_service.shutdown_and_drain().await;
            recall_worker.abort();
            let _ = (&mut recall_worker).await;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            server_result??;
            Err("server stopped unexpectedly".into())
        }
        result = &mut writer_task => {
            let _ = shutdown_tx.send(true);
            recovery_action_service.shutdown_and_drain().await;
            recall_worker.abort();
            let _ = (&mut recall_worker).await;
            task.await??;
            result??;
            Err("writer stopped unexpectedly".into())
        }
        result = &mut recall_worker => {
            let _ = shutdown_tx.send(true);
            recovery_action_service.shutdown_and_drain().await;
            task.await??;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            result?;
            Err("recall worker stopped unexpectedly".into())
        }
        signal = wait_for_signal() => {
            signal?;
            let _ = shutdown_tx.send(true);
            recovery_action_service.shutdown_and_drain().await;
            task.await??;
            recall_worker.abort();
            let _ = (&mut recall_worker).await;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            Ok(())
        }
    }
}

fn map_mcp_result(result: McpServiceResult) -> McpResultEnvelope {
    let status = match result.status {
        McpServiceStatus::Ok => McpStatus::Ok,
        McpServiceStatus::NoMatch => McpStatus::NoMatch,
        McpServiceStatus::NoRecallNeeded => McpStatus::NoRecallNeeded,
        McpServiceStatus::Partial => McpStatus::Partial,
        McpServiceStatus::DegradedIndex => McpStatus::DegradedIndex,
        McpServiceStatus::ScopeUnresolved => McpStatus::ScopeUnresolved,
        McpServiceStatus::Conflict => McpStatus::Conflict,
        McpServiceStatus::InvalidInput => McpStatus::InvalidInput,
        McpServiceStatus::NotFound => McpStatus::NotFound,
    };
    McpResultEnvelope {
        schema_version: 1,
        request_id: result.request_id,
        status,
        scope: result.scope,
        freshness: result.freshness,
        completeness: result.completeness,
        items: {
            let mut partitions = McpItems::default();
            for item in result.items {
                let partition = item.partition;
                let item = McpItem {
                    kind: item.kind,
                    object_ref: item.object_ref,
                    object_revision_ref: item.object_revision_ref,
                    source_revision_ref: item.source_revision_ref,
                    scope: item.scope,
                    applicability: item.applicability,
                    authority: item.authority,
                    text: item.text,
                    content_trust: item.content_trust,
                    capture_completeness: item.capture_completeness,
                    instruction_authority: item.instruction_authority,
                };
                match partition {
                    evertrace_engine::McpItemPartition::NormativeConstraint => {
                        partitions.normative_constraints.push(item)
                    }
                    evertrace_engine::McpItemPartition::Procedure => {
                        partitions.procedures.push(item)
                    }
                    evertrace_engine::McpItemPartition::Evidence => partitions.evidence.push(item),
                    evertrace_engine::McpItemPartition::Warning => partitions.warnings.push(item),
                }
            }
            partitions
        },
        warnings: result.warnings,
        truncated: result.truncated,
        next_refs: result.next_refs,
        audit_ref: None,
    }
}

const fn map_unsupported_reason(reason: EngineUnsupportedReason) -> RecoveryUnsupportedReason {
    match reason {
        EngineUnsupportedReason::UnsupportedApplicationKind => {
            RecoveryUnsupportedReason::UnsupportedApplicationKind
        }
        EngineUnsupportedReason::AmbiguousPatchContent => {
            RecoveryUnsupportedReason::AmbiguousPatchContent
        }
        EngineUnsupportedReason::UnsupportedPatchShape => {
            RecoveryUnsupportedReason::UnsupportedPatchShape
        }
        EngineUnsupportedReason::RedactedContent => RecoveryUnsupportedReason::RedactedContent,
        EngineUnsupportedReason::IncompleteBundle => RecoveryUnsupportedReason::IncompleteBundle,
        EngineUnsupportedReason::TargetUnavailable => RecoveryUnsupportedReason::TargetUnavailable,
        EngineUnsupportedReason::PatchPreflightFailed => {
            RecoveryUnsupportedReason::PatchPreflightFailed
        }
        EngineUnsupportedReason::PhysicalPreflightUnavailable => {
            RecoveryUnsupportedReason::PhysicalPreflightUnavailable
        }
        EngineUnsupportedReason::PhysicalPreflightRaced => {
            RecoveryUnsupportedReason::PhysicalPreflightRaced
        }
    }
}

fn map_recovery_error(error: RecoveryError) -> ErrorCode {
    match error {
        RecoveryError::GateInactive | RecoveryError::NotAdmitted => ErrorCode::Untrusted,
        RecoveryError::PendingUnavailable => ErrorCode::PendingImport,
        RecoveryError::FenceBusy | RecoveryError::StaleCurrent => ErrorCode::Conflict,
        RecoveryError::Spool | RecoveryError::Budget | RecoveryError::Deadline => {
            ErrorCode::ResourceExhausted
        }
        RecoveryError::InvalidInput | RecoveryError::InvalidSuccessor => ErrorCode::InvalidInput,
        RecoveryError::Store => ErrorCode::StoreCorrupt,
        RecoveryError::Protection
        | RecoveryError::Cas
        | RecoveryError::InvalidBundle
        | RecoveryError::Probe => ErrorCode::Internal,
    }
}

struct StartupArgs {
    config: Option<PathBuf>,
    maintenance: bool,
}

impl StartupArgs {
    fn parse() -> Result<Self, &'static str> {
        let mut values = env::args_os().skip(1);
        let mut config = None;
        let mut maintenance = false;
        while let Some(value) = values.next() {
            if value == "--config" && config.is_none() {
                config = Some(PathBuf::from(
                    values.next().ok_or("--config requires a path")?,
                ));
            } else if value == "--maintenance" && !maintenance {
                maintenance = true;
            } else {
                return Err("usage: evertraced [--config PATH] [--maintenance]");
            }
        }
        Ok(Self {
            config,
            maintenance,
        })
    }
}

fn config_path(explicit: Option<PathBuf>) -> Result<PathBuf, &'static str> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = env::var_os("EVERTRACE_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    default_config_path().ok_or("no platform configuration directory")
}

fn default_config_path() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("evertrace/config.toml"))
}

async fn wait_for_signal() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
