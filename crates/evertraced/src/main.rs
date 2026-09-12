#![forbid(unsafe_code)]
#![deny(warnings)]

mod mcp_output;

use std::{
    env, fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use evertrace_engine::{
    BackgroundScheduler, EngineService, HealthDispatchError,
    HumanActionOutcome as EngineHumanActionOutcome, HumanBackupSummary as EngineHumanBackupSummary,
    HumanBackupValidationResult as EngineHumanBackupValidationResult,
    HumanCompetingDetail as EngineHumanCompetingDetail,
    HumanExecutionIntegrityDetail as EngineHumanExecutionIntegrityDetail,
    HumanForgetPreview as EngineHumanForgetPreview, HumanGovernanceError, HumanGovernanceService,
    HumanItemCategory as EngineHumanItemCategory, HumanJobDetail as EngineHumanJobDetail,
    HumanJobState as EngineHumanJobState, HumanJobTerminalReason as EngineHumanJobTerminalReason,
    HumanNegativeDecision as EngineHumanNegativeDecision,
    HumanObjectFamily as EngineHumanObjectFamily,
    HumanProposalDecision as EngineHumanProposalDecision,
    HumanRecoveryDetail as EngineHumanRecoveryDetail, HumanRelatedRequest,
    HumanRelationKind as EngineHumanRelationKind,
    HumanRepositoryPurgePreview as EngineHumanRepositoryPurgePreview,
    HumanRowClass as EngineHumanRowClass, HumanSupportDetail as EngineHumanSupportDetail,
    HumanSurface as EngineHumanSurface, HumanSystemDetail as EngineHumanSystemDetail,
    McpActionService, McpBindingAuthority, McpBindingIssue, McpServiceAction, McpServiceRequest,
    McpServiceResult, McpServiceStatus, RecallCueOutcome, RecallCueService, RecoveryActionOutcome,
    RecoveryActionService, RecoveryBarrierLocator as EngineRecoveryLocator, RecoveryBarrierService,
    RecoveryError, RecoveryRequest, RecoveryUnsupportedReason as EngineUnsupportedReason,
    RuntimeMode, SessionImportWorker, open_writer,
    recall::spawn_recall_worker_with_config,
    repository::observe_session_catalog_report,
    session_import::{
        SessionCatalogService, SessionImportAdminAction as EngineSessionImportAdminAction,
        SessionImportAdminOutcome, SessionImportAdminService,
    },
    spawn_writer,
};
use evertrace_protocol::{
    LocalServer, ServerOptions,
    command::{Command as ProtocolCommand, RecallCueCommand, SessionImportAdminAction},
    dto::{
        ClientKind, HealthMode, HumanActionRequest, HumanActionResult, HumanActionStatus,
        HumanBackupSummary, HumanBackupTableState, HumanBackupValidationResult,
        HumanCompetingDetail, HumanDegradedReason, HumanExecutionIntegrityDetail,
        HumanForgetPreview, HumanGovernanceRequest, HumanGovernanceResponse, HumanItemCategory,
        HumanItemKind, HumanJobBudget, HumanJobDetail, HumanJobState, HumanJobTerminalReason,
        HumanNegativeReviewMetadata, HumanObjectFamily, HumanProposalMetadata, HumanProposalReview,
        HumanReadRequest, HumanRecoveryDetail, HumanRecoveryOmissionCount, HumanRelationKind,
        HumanRepositoryPurgePreview, HumanRowClass, HumanSnapshotItem, HumanSnapshotStatus,
        HumanSupportDetail, HumanSurface, HumanSystemDetail, HumanWorktreeDetail,
        NegativeReviewDecision, PROTOCOL_VERSION, ProposalHumanDecision,
    },
    envelope::{McpItem, McpItems, McpResultEnvelope, McpStatus},
    error::ErrorCode,
    resolve_data_dir,
    response::{
        HealthResponse, McpBindingIssuedResponse, RecallCueResponse, RecoveryActionResponse,
        RecoveryTerminalResponse, RecoveryUnsupportedReason, Response, SessionImportAdminResponse,
    },
};
use tokio::sync::{RwLock, mpsc, watch};
use tracing_subscriber::{Layer, layer::SubscriberExt};

fn lifecycle_filter<S>(engine: Arc<EngineService>) -> impl tracing_subscriber::layer::Filter<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // Dynamic interest is essential: a disabled callsite must become enabled
    // after a reload. Never enable arbitrary dependency/body logging.
    tracing_subscriber::filter::dynamic_filter_fn(move |metadata, _| {
        metadata.target() == "evertrace_lifecycle" && *metadata.level() <= engine.log_level()
    })
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("evertraced: {error}");
        std::process::exit(1);
    }
}

fn map_host_canary(
    value: evertrace_engine::HostCanaryDiagnostic,
) -> evertrace_protocol::dto::HostCanaryDiagnostic {
    use evertrace_engine::HostCanaryStatus as Source;
    use evertrace_protocol::dto::HostCanaryStatus as Target;
    evertrace_protocol::dto::HostCanaryDiagnostic {
        scope: match value.scope {
            evertrace_engine::HostCanaryScope::Installed => {
                evertrace_protocol::dto::HostCanaryScope::Installed
            }
            evertrace_engine::HostCanaryScope::Candidate {
                check_id,
                generation,
            } => evertrace_protocol::dto::HostCanaryScope::Candidate {
                check_id,
                generation,
            },
        },
        status: match value.status {
            Source::NotRun => Target::NotRun,
            Source::Running => Target::Running,
            Source::Unavailable => Target::Unavailable,
            Source::BudgetExceeded => Target::BudgetExceeded,
            Source::EvidenceMissing => Target::EvidenceMissing,
            Source::TimedOut => Target::TimedOut,
            Source::IdentityChanged => Target::IdentityChanged,
            Source::Interrupted => Target::Interrupted,
            Source::Observed => Target::Observed,
        },
        native_delivery_observed: value.native_delivery_observed,
        mcp_claim_consumed: value.mcp_claim_consumed,
        capture_receipt_observed: value.capture_receipt_observed,
        // Only the fixed display projection crosses the protocol boundary;
        // the evaluated report/evidence remains owned by this daemon.
        qualification: value.qualification.map(|value| {
            serde_json::from_value(
                serde_json::to_value(value).expect("qualification serialization"),
            )
            .expect("closed qualification DTO matches adapter codes")
        }),
    }
}

fn map_config_reload(result: evertrace_engine::ConfigReloadResult) -> Response {
    Response::ConfigReload(evertrace_protocol::response::ConfigReloadResponse {
        active_hash: result.active_hash,
        pending_hash: result.pending_hash,
        outcome: match result.outcome {
            evertrace_engine::ConfigReloadOutcome::Prepared => {
                evertrace_protocol::dto::ConfigReloadOutcome::Prepared
            }
            evertrace_engine::ConfigReloadOutcome::Applied => {
                evertrace_protocol::dto::ConfigReloadOutcome::Applied
            }
            evertrace_engine::ConfigReloadOutcome::Rejected => {
                evertrace_protocol::dto::ConfigReloadOutcome::Rejected
            }
            evertrace_engine::ConfigReloadOutcome::RestartRequired => {
                evertrace_protocol::dto::ConfigReloadOutcome::RestartRequired
            }
        },
    })
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let raw = env::args_os().skip(1).collect::<Vec<_>>();
    if raw
        .first()
        .is_some_and(|value| value == "--verify-package-native")
    {
        if raw.len() != 4 || raw[2] != "--cas" {
            return Err("usage: evertraced --verify-package-native PATH --cas PATH".into());
        }
        evertrace_engine::maintenance::verify_package_native(
            std::path::Path::new(&raw[1]),
            std::path::Path::new(&raw[3]),
        )
        .await?;
        println!("candidate native verified");
        return Ok(());
    }
    let args = StartupArgs::parse()?;
    let config_path = config_path(args.config)?;
    let source = fs::read_to_string(&config_path)?;
    let mode = if args.maintenance {
        RuntimeMode::Maintenance
    } else {
        RuntimeMode::Normal
    };
    let engine = Arc::new(EngineService::from_toml(&source, mode)?);
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(lifecycle_filter(Arc::clone(&engine))),
    );
    tracing::subscriber::set_global_default(subscriber)?;
    tracing::info!(target: "evertrace_lifecycle", "daemon starting");
    if args.candidate.is_some() && engine.effective_config().config().llm.enabled {
        return Err("candidate daemon requires llm.enabled=false".into());
    }
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(&engine.data_dir(), home.as_deref(), |name| {
        env::var_os(name)
    })?;
    if args.candidate.is_some() {
        let candidate_config = std::path::absolute(&config_path)?;
        // At most the explicit config may pre-exist; reject any native/other
        // user asset before publishing runtime or opening a writer.
        for entry in fs::read_dir(&data_dir)? {
            if entry?.path() != candidate_config {
                return Err("candidate daemon requires a fresh disposable root".into());
            }
        }
    }
    let writer = open_writer(&data_dir).await?;
    let (writer_handle, mut writer_task) = spawn_writer(writer, 64)?;
    let config_reload = Arc::new(evertrace_engine::ConfigReloadService::new(
        Arc::clone(&engine),
        writer_handle.clone(),
        data_dir.clone(),
        std::path::absolute(&config_path)?,
    )?);
    let runtime_snapshot = config_reload.initialize_runtime().await?;
    evertrace_engine::initialize_runtime_spool(&runtime_snapshot)?;
    let current_session_catalog_report = Arc::new(RwLock::new(None));
    let mut recall_worker = spawn_recall_worker_with_config(
        writer_handle.clone(),
        runtime_snapshot.clone(),
        data_dir.clone(),
        Some(Arc::clone(&config_reload)),
        Some(Arc::clone(&current_session_catalog_report)),
    );
    let mcp_bindings = McpBindingAuthority::from_device_key_dir(&runtime_snapshot.device_key_dir)?;
    let mut host_canary = evertrace_engine::HostCanaryService::new(
        writer_handle.clone(),
        data_dir.clone(),
        std::path::absolute(&config_path)?,
        runtime_snapshot.effective_config_hash,
        mcp_bindings.clone(),
    );
    if let Some((check_id, generation)) = args.candidate {
        let executable = env::current_exe()?;
        host_canary = host_canary.with_candidate(
            check_id,
            generation,
            executable
                .parent()
                .ok_or("candidate package unavailable")?
                .to_owned(),
        )?;
    }
    let session_import_admin = SessionImportAdminService::new(
        writer_handle.clone(),
        Arc::clone(&current_session_catalog_report),
        runtime_snapshot.effective_config_hash,
    );
    let session_catalog = SessionCatalogService::new(
        writer_handle.clone(),
        runtime_snapshot.effective_config_hash,
    );
    let session_import_worker = SessionImportWorker::new(
        writer_handle.clone(),
        runtime_snapshot.clone(),
        Arc::clone(&current_session_catalog_report),
    )?;
    let human_governance = HumanGovernanceService::with_acceptance(
        writer_handle.clone(),
        runtime_snapshot.effective_config_hash,
        runtime_snapshot.clone(),
        engine.effective_config().config().global_promotion.clone(),
    )
    .with_session_report(Arc::clone(&current_session_catalog_report))
    .with_inventory_bindings(mcp_bindings.clone());
    human_governance.reconcile_reserved_once().await?;
    let (session_import_wakeup_tx, session_import_wakeup_rx) = watch::channel(0_u64);
    let (session_import_shutdown_tx, session_import_shutdown_rx) = watch::channel(false);
    let (backup_request_tx, mut backup_request_rx) = mpsc::channel(1);
    let dispatch_gate = Arc::new(RwLock::new(()));
    let scheduler = BackgroundScheduler::new(
        writer_handle.clone(),
        session_catalog,
        session_import_worker,
        Arc::clone(&current_session_catalog_report),
        runtime_snapshot.clone(),
        engine.synthesis_planner(),
        engine.effective_config().config().dreaming.clone(),
    )
    .with_dispatch(Arc::clone(&dispatch_gate))
    .with_backup_requests(backup_request_tx)
    .with_inventory(evertrace_engine::jobs::InventoryWorker::new(
        writer_handle.clone(),
        runtime_snapshot.clone(),
        mcp_bindings.clone(),
    ))
    .with_config(Arc::clone(&config_reload));
    let mut background_scheduler_task =
        tokio::spawn(scheduler.run(session_import_wakeup_rx, session_import_shutdown_rx));
    let mcp_service = McpActionService::open(
        mcp_bindings.clone(),
        &data_dir,
        writer_handle.clone(),
        runtime_snapshot.clone(),
    )
    .await?
    .with_session_report(Arc::clone(&current_session_catalog_report));
    let recovery_service =
        RecoveryBarrierService::new(runtime_snapshot.clone(), writer_handle.clone());
    let recall_cue_service = RecallCueService::new(
        writer_handle.clone(),
        runtime_snapshot.recall_cue_gate,
        runtime_snapshot.recall_cue_adapter_manifest_id.clone(),
        runtime_snapshot.generation,
        runtime_snapshot.effective_config_hash,
        &data_dir,
    )
    .with_session_report(Arc::clone(&current_session_catalog_report));
    let recovery_action_service = RecoveryActionService::new(
        runtime_snapshot.clone(),
        writer_handle.clone(),
        recovery_service.mutation_fence(),
    )
    .with_session_report(Arc::clone(&current_session_catalog_report));
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
    let maintenance_active = Arc::new(AtomicBool::new(false));
    let ingestor = evertrace_engine::EvidenceIngestor::new(
        runtime_snapshot.clone(),
        writer_handle.as_ref().ok_or("writer unavailable")?.clone(),
        runtime_snapshot.effective_config_hash,
        "ordinary-hook-ingest-v1",
    )?
    .with_config(Arc::clone(&config_reload))
    .with_recovery_wakeup(session_import_wakeup_tx.clone());
    let mut ingest_task = tokio::spawn(ingestor.run(
        Arc::clone(&dispatch_gate),
        session_import_shutdown_tx.subscribe(),
    ));
    let handler_engine = Arc::clone(&engine);
    let handler_recovery_action_service = recovery_action_service.clone();
    let handler_mcp_bindings = mcp_bindings;
    let handler_mcp_service = mcp_service;
    let handler_session_catalog_report = Arc::clone(&current_session_catalog_report);
    let handler_session_import_admin = session_import_admin;
    let handler_human_governance = human_governance;
    let handler_session_import_wakeup = session_import_wakeup_tx.clone();
    let handler_maintenance_active = Arc::clone(&maintenance_active);
    let handler_dispatch_gate = Arc::clone(&dispatch_gate);
    let handler_shutdown = shutdown_tx.clone();
    let handler_config_reload = Arc::clone(&config_reload);
    let mut task = tokio::spawn(server.run_dispatch_with_context(
        shutdown_rx,
        move |context, request_id, command| {
            let handler_engine = Arc::clone(&handler_engine);
            let config_reload = Arc::clone(&handler_config_reload);
            let config_shutdown = handler_shutdown.clone();
            let recovery_service = recovery_service.clone();
            let recovery_action_service = handler_recovery_action_service.clone();
            let mcp_bindings = handler_mcp_bindings.clone();
            let host_canary = host_canary.clone();
            let mcp_service = handler_mcp_service.clone();
            let recall_cue_service = recall_cue_service.clone();
            let session_catalog_report = Arc::clone(&handler_session_catalog_report);
            let session_import_admin = handler_session_import_admin.clone();
            let human_governance = handler_human_governance.clone();
            let session_import_wakeup = handler_session_import_wakeup.clone();
            let maintenance_active = Arc::clone(&handler_maintenance_active);
            let dispatch_gate = Arc::clone(&handler_dispatch_gate);
            async move {
                if maintenance_active.load(Ordering::Acquire) {
                    if !matches!(&command, ProtocolCommand::Health) {
                        return Err(ErrorCode::MaintenanceMode);
                    }
                    let config = config_reload.admit().await.map_err(|_| ErrorCode::MaintenanceMode)?;
                    let snapshot = handler_engine.health().map_err(|_| ErrorCode::MaintenanceMode)?;
                    return Ok(Response::Health(HealthResponse {
                        protocol_version: PROTOCOL_VERSION,
                        mode: HealthMode::Maintenance,
                        config_version: config.config().config_version,
                        effective_config_hash: hex(&config.hash()),
                        algorithm_revision: snapshot.algorithm_revision,
                        host_canary: host_canary.current().map(map_host_canary),
                    }));
                }
                let _dispatch = dispatch_gate.read_owned().await;
                if maintenance_active.load(Ordering::Acquire) {
                    return Err(ErrorCode::MaintenanceMode);
                }
                let config_snapshot = config_reload.admit().await.map_err(|_| ErrorCode::MaintenanceMode)?;
                let mcp_service = mcp_service.for_config(&config_snapshot).map_err(|_| ErrorCode::Internal)?;
                let human_governance = human_governance.for_config(&config_snapshot).map_err(|_| ErrorCode::Internal)?;
                let recovery_service = recovery_service.for_config(&config_snapshot).map_err(|_| ErrorCode::Internal)?;
                let recovery_action_service = recovery_action_service.for_config(&config_snapshot).map_err(|_| ErrorCode::Internal)?;
                let recall_cue_service = recall_cue_service.for_config(&config_snapshot);
                let session_import_admin = session_import_admin.for_config(&config_snapshot);
                let host_canary = host_canary.for_config(&config_snapshot);
                match command {
                    ProtocolCommand::RunHostCanary(request) => {
                        if context.client_kind != ClientKind::Cli { return Err(ErrorCode::Untrusted); }
                        Ok(Response::HostCanary(map_host_canary(host_canary.run(evertrace_engine::HostCanaryRequest {
                            host_executable: request.host_executable, host_config: request.host_config,
                        }).await)))
                    }
                    ProtocolCommand::Health => {
                        let snapshot = handler_engine.health().map_err(|error| match error {
                            HealthDispatchError::MaintenanceMode => ErrorCode::MaintenanceMode,
                        })?;
                        Ok(Response::Health(HealthResponse {
                            protocol_version: PROTOCOL_VERSION,
                            mode: HealthMode::Normal,
                            config_version: config_snapshot.config().config_version,
                            effective_config_hash: hex(&config_snapshot.hash()),
                            algorithm_revision: snapshot.algorithm_revision,
                            host_canary: host_canary.current().map(map_host_canary),
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
                        if context.client_kind != ClientKind::Cli {
                            return Err(ErrorCode::Untrusted);
                        }
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
                        let observed = observe_session_catalog_report(
                            issue.transcript_path.as_deref(),
                            &issue.session_id,
                            &issue.tool_use_id,
                            issue.agent_id.as_deref(),
                        )
                        .ok();
                        let grant = mcp_bindings
                            .issue_with_report(McpBindingIssue {
                                session_id: issue.session_id,
                                turn_id: issue.turn_id,
                                tool_use_id: issue.tool_use_id,
                                agent_id: issue.agent_id,
                                action: issue.original_input.action.as_str().into(),
                                workspace: issue.original_input.workspace,
                                input: issue.original_input.input,
                                refs: issue.original_input.refs,
                                launcher_protocol_revision: issue.launcher_protocol_revision,
                            }, observed.clone().map(Arc::new))
                            .map_err(|_| ErrorCode::Untrusted)?;
                        *session_catalog_report.write().await = observed;
                        let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                        session_import_wakeup.send_replace(next);
                        Ok(Response::McpBindingIssued(McpBindingIssuedResponse {
                            bound_workspace: grant.bound_workspace,
                            expires_at_us: grant.expires_at_us,
                        }))
                    }
                    ProtocolCommand::ConfigRead => {
                        if context.client_kind != ClientKind::Cli { return Err(ErrorCode::Untrusted); }
                        let (source, file_hash) = config_reload.read_editable().map_err(|_| ErrorCode::InvalidInput)?;
                        Ok(Response::ConfigDocument(evertrace_protocol::response::ConfigDocumentResponse { source, file_hash }))
                    }
                    ProtocolCommand::ConfigWrite(write) => {
                        if context.client_kind != ClientKind::Cli { return Err(ErrorCode::Untrusted); }
                        let result = config_reload.write_optimistic(&write.source, &write.expected_file_hash).await.map_err(|error| {
                            if matches!(error, evertrace_engine::ConfigReloadError::Stopped) { let _ = config_shutdown.send(true); }
                            ErrorCode::InvalidInput
                        })?;
                        let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                        session_import_wakeup.send_replace(next);
                        tracing::info!(target: "evertrace_lifecycle", outcome = ?result.outcome, "configuration result");
                        Ok(map_config_reload(result))
                    }
                    ProtocolCommand::ConfigReload => {
                        if context.client_kind != ClientKind::Cli { return Err(ErrorCode::Untrusted); }
                        let source = evertrace_engine::ConfigReloadSource::Cli;
                        let result = config_reload.reload(source).await.map_err(|error| {
                            if matches!(error, evertrace_engine::ConfigReloadError::Stopped) { let _ = config_shutdown.send(true); }
                            ErrorCode::InvalidInput
                        })?;
                        if result.outcome == evertrace_engine::ConfigReloadOutcome::Applied {
                            let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                            session_import_wakeup.send_replace(next);
                        }
                        tracing::info!(target: "evertrace_lifecycle", outcome = ?result.outcome, "configuration result");
                        Ok(map_config_reload(result))
                    }
                    ProtocolCommand::McpCall(call) => {
                        if context.client_kind != ClientKind::Mcp {
                            return Err(ErrorCode::Untrusted);
                        }
                        let output_action = call.input.action;
                        let action = match call.input.action {
                            evertrace_protocol::mcp::McpAction::Search => McpServiceAction::Search,
                            evertrace_protocol::mcp::McpAction::Get => McpServiceAction::Get,
                            evertrace_protocol::mcp::McpAction::Add => McpServiceAction::Add,
                            evertrace_protocol::mcp::McpAction::Organize => {
                                McpServiceAction::Organize
                            }
                        };
                        let result = mcp_service
                            .for_native_peer(
                                context.peer_credentials.map(|peer| evertrace_engine::repository::NativeHostPeer {
                                    pid: peer.pid, uid: peer.uid, gid: peer.gid,
                                }),
                                std::sync::Arc::downgrade(&context.connection_lifetime),
                            )
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
                        let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                        session_import_wakeup.send_replace(next);
                        let target_bytes = match output_action {
                            evertrace_protocol::mcp::McpAction::Search => {
                                config_snapshot.config().search.search_token_budget as usize * 4
                            }
                            evertrace_protocol::mcp::McpAction::Get => {
                                config_snapshot.config().search.get_token_budget as usize * 4
                            }
                            _ => 2_400,
                        };
                        let mut result = map_mcp_result(result);
                        mcp_output::bound_result(&mut result, output_action, target_bytes);
                        Ok(Response::McpResult(Box::new(result)))
                    }
                    ProtocolCommand::McpReturned { request_id: original_request } => {
                        let Some((expected, revisions)) = context.mcp_returned else {
                            return Err(ErrorCode::Untrusted);
                        };
                        if context.client_kind != ClientKind::Mcp || expected != original_request {
                            return Err(ErrorCode::Untrusted);
                        }
                        mcp_service.confirm_procedure_return(original_request, request_id, &revisions)
                            .await.map_err(|_| ErrorCode::Internal)?;
                        Ok(Response::McpReturned)
                    }
                    ProtocolCommand::SessionImportAdmin(command) => {
                        if context.client_kind != ClientKind::Cli {
                            return Err(ErrorCode::Untrusted);
                        }
                        let action = match command.action {
                            SessionImportAdminAction::QueueImport => {
                                EngineSessionImportAdminAction::QueueImport
                            }
                            SessionImportAdminAction::RevokeAccess => {
                                EngineSessionImportAdminAction::RevokeAccess
                            }
                        };
                        let occurred_at_us = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .and_then(|value| i64::try_from(value.as_micros()).ok())
                            .ok_or(ErrorCode::Internal)?;
                        let session_id = command.session_id;
                        let outcome = session_import_admin
                            .handle(request_id, &session_id, action, occurred_at_us)
                            .await
                            .map_err(|_| ErrorCode::InvalidInput)?;
                        if matches!(outcome, SessionImportAdminOutcome::Queued | SessionImportAdminOutcome::Partial { changed: 1.., .. }) {
                            let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                            session_import_wakeup.send_replace(next);
                        }
                        Ok(Response::SessionImportAdmin(match outcome {
                            SessionImportAdminOutcome::Partial { changed, unavailable, remaining } => SessionImportAdminResponse::Partial { changed, unavailable, remaining },
                            SessionImportAdminOutcome::Queued => SessionImportAdminResponse::Queued,
                            SessionImportAdminOutcome::Revoked => {
                                SessionImportAdminResponse::Revoked
                            }
                            SessionImportAdminOutcome::NoDelta => {
                                SessionImportAdminResponse::NoDelta
                            }
                        }))
                    }
                    ProtocolCommand::HumanGovernance(command) => {
                        if context.client_kind != ClientKind::Cli {
                            return Err(ErrorCode::Untrusted);
                        }
                        if !command.validate() {
                            return Err(ErrorCode::InvalidInput);
                        }
                        let response = match command {
                            HumanGovernanceRequest::Export { selections } => {
                                let result = human_governance.export(selections.into_iter().map(|item| evertrace_engine::HumanExportSelection {
                                    object_ref: item.object_ref,
                                    expected_revision_ref: item.expected_revision_ref,
                                }).collect()).await;
                                HumanGovernanceResponse::Export {
                                    result: evertrace_protocol::dto::HumanExportResult {
                                        status: match result.status {
                                            evertrace_engine::HumanExportStatus::Published => evertrace_protocol::dto::HumanExportStatus::Published,
                                            evertrace_engine::HumanExportStatus::PublicationUncertain => evertrace_protocol::dto::HumanExportStatus::PublicationUncertain,
                                            evertrace_engine::HumanExportStatus::Conflict => evertrace_protocol::dto::HumanExportStatus::Conflict,
                                            evertrace_engine::HumanExportStatus::Denied => evertrace_protocol::dto::HumanExportStatus::Denied,
                                            evertrace_engine::HumanExportStatus::Failed => evertrace_protocol::dto::HumanExportStatus::Failed,
                                        },
                                        path: result.path,
                                        frontier: result.frontier,
                                        object_count: result.object_count,
                                        total_bytes: result.total_bytes,
                                        reason: result.reason.map(str::to_owned),
                                    },
                                }
                            }
                            HumanGovernanceRequest::Read { request } => match request {
                                HumanReadRequest::List {
                                    surface,
                                    expected_frontier,
                                    after,
                                    limit,
                                } => match if surface == HumanSurface::System {
                                    human_governance.list_system(&config_snapshot, host_canary.current(),
                                        expected_frontier, after.as_deref(), limit).await
                                } else { human_governance.list(
                                        map_human_surface(surface),
                                        expected_frontier,
                                        after.as_deref(),
                                        limit,
                                    ).await }
                                    .map_err(map_human_error)?
                                {
                                    Ok(page) => map_human_page(page),
                                    Err(current_frontier) => {
                                        HumanGovernanceResponse::Conflict {
                                            current_frontier,
                                            current_revision_ref: None,
                                        }
                                    }
                                },
                                HumanReadRequest::Detail {
                                    surface,
                                    object_ref,
                                    expected_frontier,
                                    expected_revision_ref,
                                } => match human_governance
                                        .detail(
                                            map_human_surface(surface),
                                            &object_ref,
                                            expected_frontier,
                                            expected_revision_ref.as_deref(),
                                        )
                                        .await
                                        .map_err(map_human_error)?
                                    {
                                        Ok(page) => map_human_page(page),
                                        Err((current_frontier, current_revision_ref)) => {
                                            HumanGovernanceResponse::Conflict {
                                                current_frontier,
                                                current_revision_ref,
                                            }
                                        }
                                    },
                                HumanReadRequest::Related {
                                    relation,
                                    source_stable_key,
                                    expected_source_revision_ref,
                                    expected_frontier,
                                    after,
                                    limit,
                                } => match human_governance
                                    .related(HumanRelatedRequest {
                                        relation: match relation {
                                            HumanRelationKind::ProposalEvidence => {
                                                EngineHumanRelationKind::ProposalEvidence
                                            }
                                            HumanRelationKind::SupportDependencies => {
                                                EngineHumanRelationKind::SupportDependencies
                                            }
                                        },
                                        source_stable_key: &source_stable_key,
                                        expected_source_revision_ref: &expected_source_revision_ref,
                                        expected_frontier,
                                        after: after.as_deref(),
                                        limit,
                                    })
                                    .await
                                    .map_err(map_human_error)?
                                {
                                    Ok(page) => map_human_page(page),
                                    Err((current_frontier, current_revision_ref)) => {
                                        HumanGovernanceResponse::Conflict {
                                            current_frontier,
                                            current_revision_ref,
                                        }
                                    }
                                },
                            },
                            HumanGovernanceRequest::Act {
                                expected_frontier,
                                action,
                            } => {
                                let outcome = match action {
                                    HumanActionRequest::Proposal {
                                        proposal_id,
                                        expected_revision_id,
                                        expected_fingerprint,
                                        decision,
                                        edited_payload,
                                    } => {
                                        let decision = match (decision, edited_payload) {
                                            (ProposalHumanDecision::Accept, None) => {
                                                Ok(EngineHumanProposalDecision::Accept)
                                            }
                                            (
                                                ProposalHumanDecision::EditAndAccept,
                                                Some(payload),
                                            ) => Ok(EngineHumanProposalDecision::EditAndAccept(
                                                payload,
                                            )),
                                            (ProposalHumanDecision::Reauthorize, None) => {
                                                Ok(EngineHumanProposalDecision::Reauthorize)
                                            }
                                            (ProposalHumanDecision::MergeAndAccept, None) => {
                                                Ok(EngineHumanProposalDecision::MergeAndAccept)
                                            }
                                            (ProposalHumanDecision::Defer, None) => {
                                                Ok(EngineHumanProposalDecision::Defer)
                                            }
                                            (ProposalHumanDecision::Reject, None) => {
                                                Ok(EngineHumanProposalDecision::Reject)
                                            }
                                            _ => Err(HumanGovernanceError::InvalidInput),
                                        };
                                        match decision {
                                            Ok(decision) => {
                                                human_governance
                                                    .decide_proposal(
                                                        request_id,
                                                        expected_frontier,
                                                        proposal_id,
                                                        expected_revision_id,
                                                        &expected_fingerprint,
                                                        decision,
                                                    )
                                                    .await
                                            }
                                            Err(error) => Err(error),
                                        }
                                    }
                                    HumanActionRequest::NegativeReview {
                                        negative_evidence_id,
                                        expected_review_revision_id,
                                        decision,
                                    } => {
                                        let decision = match decision {
                                            NegativeReviewDecision::ResolveAsIneffective => {
                                                EngineHumanNegativeDecision::ResolveAsIneffective
                                            }
                                            NegativeReviewDecision::DismissAttribution => {
                                                EngineHumanNegativeDecision::DismissAttribution
                                            }
                                            NegativeReviewDecision::ConfirmHarm => {
                                                EngineHumanNegativeDecision::ConfirmHarm
                                            }
                                            NegativeReviewDecision::RequestRevision => {
                                                EngineHumanNegativeDecision::RequestRevision
                                            }
                                        };
                                        human_governance
                                            .review_negative(
                                                request_id,
                                                expected_frontier,
                                                negative_evidence_id,
                                                expected_review_revision_id,
                                                decision,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::SupportReplacement {
                                        expected_validation_revision_id,
                                        edited_payload,
                                    } => {
                                        human_governance
                                            .submit_support_replacement(
                                                request_id,
                                                expected_frontier,
                                                expected_validation_revision_id,
                                                *edited_payload,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::SupportDeprecate {
                                        expected_validation_revision_id,
                                        reason,
                                    } => {
                                        human_governance
                                            .submit_support_deprecate(
                                                request_id,
                                                expected_frontier,
                                                expected_validation_revision_id,
                                                reason,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::ResolveCompetingSelected {
                                        expected_group_revision_id,
                                        chosen_attempt_id,
                                    } => {
                                        human_governance
                                            .resolve_competing_selected(
                                                request_id,
                                                expected_frontier,
                                                expected_group_revision_id,
                                                chosen_attempt_id,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::MarkNewAttempt {
                                        expected_attempt_revision_id,
                                    } => {
                                        human_governance
                                            .mark_new_attempt(
                                                request_id,
                                                expected_frontier,
                                                expected_attempt_revision_id,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::ForgetObject {
                                        target,
                                        expected_revision_ids,
                                        expected_deletion_generation,
                                    } => {
                                        human_governance
                                            .forget_object(
                                                request_id,
                                                expected_frontier,
                                                target,
                                                expected_revision_ids,
                                                expected_deletion_generation,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::PurgeRepository {
                                        repository_id,
                                        repository_confirmation,
                                        expected_repository_revision,
                                        expected_deletion_generation,
                                    } => {
                                        human_governance
                                            .purge_repository(
                                                request_id,
                                                expected_frontier,
                                                repository_id,
                                                &repository_confirmation,
                                                expected_repository_revision,
                                                expected_deletion_generation,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::RepositoryAccess { repository_id, expected_repository_revision, action, worktree_id, inventory_ref } => {
                                        human_governance.repository_access(request_id, expected_frontier,
                                            evertrace_engine::HumanRepositoryAccess {
                                                repository_id, expected_repository_revision, worktree_id, inventory_ref,
                                                action: match action {
                                                    evertrace_protocol::dto::RepositoryAccessAction::Disable => evertrace_engine::HumanRepositoryAccessAction::Disable,
                                                    evertrace_protocol::dto::RepositoryAccessAction::Enable => evertrace_engine::HumanRepositoryAccessAction::Enable,
                                                    evertrace_protocol::dto::RepositoryAccessAction::Rescan => evertrace_engine::HumanRepositoryAccessAction::Rescan,
                                                },
                                            }).await
                                    }
                                    HumanActionRequest::CreateBackup => {
                                        human_governance
                                            .create_backup(request_id, expected_frontier)
                                            .await
                                    }
                                    HumanActionRequest::CollectGarbage => {
                                        human_governance.collect_garbage(request_id, expected_frontier).await
                                    }
                                    HumanActionRequest::VerifyBackup { backup_job_id } => {
                                        human_governance
                                            .verify_backup(
                                                request_id,
                                                expected_frontier,
                                                backup_job_id,
                                            )
                                            .await
                                    }
                                    HumanActionRequest::Unavailable { action } => {
                                        Ok(EngineHumanActionOutcome::Unavailable {
                                            reason: match action {
                                                evertrace_protocol::dto::HumanUnavailableAction::SupportGovernance => "support_governance_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::SegmentationCorrection => "segmentation_correction_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::LaneCorrection => "lane_correction_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::ResumeCorrection => "resume_correction_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::LineageCorrection => "lineage_correction_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::ForgetOrPurge => "forget_or_purge_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::ConfigurationWrite => "configuration_write_unavailable",
                                                evertrace_protocol::dto::HumanUnavailableAction::BackupRestoreOrGc => "offline_cli_or_future_s33",
                                            },
                                        })
                                    }
                                }
                                .map_err(map_human_error)?;
                                HumanGovernanceResponse::Action {
                                    result: map_human_action(outcome),
                                }
                            }
                        };
                        if mcp_bindings.take_inventory_wakeup() {
                            let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                            session_import_wakeup.send_replace(next);
                        }
                        Ok(Response::HumanGovernance(response))
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
    let mut config_poll = tokio::time::interval(std::time::Duration::from_secs(1));
    config_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_watch_failure = None;
    // Keep the signal receiver alive while a selected maintenance branch awaits.
    // Recreating it inside select loses signals received between loop polls.
    let shutdown_signal = wait_for_signal()?;
    tokio::pin!(shutdown_signal);
    loop {
        tokio::select! {
            _ = config_poll.tick() => {
                match config_reload.watch_once().await {
                    Ok(Some(result)) => {
                        last_watch_failure = None;
                        match result.outcome {
                            evertrace_engine::ConfigReloadOutcome::Applied => tracing::info!(target: "evertrace_lifecycle", "configuration watch applied"),
                            evertrace_engine::ConfigReloadOutcome::RestartRequired => tracing::info!(target: "evertrace_lifecycle", "configuration watch restart required"),
                            _ => tracing::warn!(target: "evertrace_lifecycle", "configuration watch rejected"),
                        }
                        let next = (*session_import_wakeup_tx.borrow()).wrapping_add(1);
                        session_import_wakeup_tx.send_replace(next);
                    }
                    Err(evertrace_engine::ConfigReloadError::Stopped) => {
                        tracing::error!(target: "evertrace_lifecycle", "configuration watch stopped: uncertain commit");
                        let _ = shutdown_tx.send(true);
                    }
                    Err(error) => {
                        let kind = match error {
                            evertrace_engine::ConfigReloadError::Busy => "busy",
                            _ => "invalid",
                        };
                        if last_watch_failure != Some(kind) {
                            tracing::warn!(target: "evertrace_lifecycle", reason = kind, "configuration watch failed");
                        }
                        last_watch_failure = Some(kind);
                    }
                    Ok(None) => { last_watch_failure = None; },
                }
            }
            result = &mut ingest_task => {
                let _ = shutdown_tx.send(true);
                let _ = session_import_shutdown_tx.send(true);
                background_scheduler_task.await??;
                recovery_action_service.shutdown_and_drain().await;
                task.await??;
                recall_worker.abort();
                let _ = (&mut recall_worker).await;
                if let Some(handle) = writer_handle.take() { handle.shutdown().await?; }
                writer_task.await??;
                result??;
                return Err("ordinary ingest stopped unexpectedly".into());
            }
            result = &mut task => {
                let server_result = result;
                let _ = session_import_shutdown_tx.send(true);
                let ingest_result = ingest_task.await;
                background_scheduler_task.await??;
                recovery_action_service.shutdown_and_drain().await;
                recall_worker.abort();
                let _ = (&mut recall_worker).await;
                if let Some(handle) = writer_handle.take() {
                    handle.shutdown().await?;
                }
                writer_task.await??;
                ingest_result??;
                server_result??;
                return Err("server stopped unexpectedly".into());
            }
            result = &mut writer_task => {
                let _ = shutdown_tx.send(true);
                let _ = session_import_shutdown_tx.send(true);
                let ingest_result = ingest_task.await;
                background_scheduler_task.await??;
                recovery_action_service.shutdown_and_drain().await;
                recall_worker.abort();
                let _ = (&mut recall_worker).await;
                task.await??;
                ingest_result??;
                result??;
                return Err("writer stopped unexpectedly".into());
            }
            result = &mut recall_worker => {
                let _ = shutdown_tx.send(true);
                let _ = session_import_shutdown_tx.send(true);
                let ingest_result = ingest_task.await;
                background_scheduler_task.await??;
                recovery_action_service.shutdown_and_drain().await;
                task.await??;
                if let Some(handle) = writer_handle.take() {
                    handle.shutdown().await?;
                }
                writer_task.await??;
                ingest_result??;
                result?;
                return Err("recall worker stopped unexpectedly".into());
            }
            result = &mut background_scheduler_task => {
                let _ = shutdown_tx.send(true);
                let _ = session_import_shutdown_tx.send(true);
                let ingest_result = ingest_task.await;
                recovery_action_service.shutdown_and_drain().await;
                task.await??;
                recall_worker.abort();
                let _ = (&mut recall_worker).await;
                if let Some(handle) = writer_handle.take() {
                    handle.shutdown().await?;
                }
                writer_task.await??;
                ingest_result??;
                result??;
                return Err("background scheduler stopped unexpectedly".into());
            }
            Some(request) = backup_request_rx.recv() => {
                maintenance_active.store(true, Ordering::Release);
                let dispatch = Arc::clone(&dispatch_gate).write_owned().await;
                recovery_action_service.quiesce_and_drain().await;
                recall_worker.abort();
                let _ = (&mut recall_worker).await;
                let result = match config_reload.backup_runtime(&runtime_snapshot).await {
                    Ok(runtime) => writer_handle
                    .as_ref()
                    .ok_or("writer unavailable during backup")?
                    .create_backup(
                        request.backup_job_id(),
                        config_path.clone(),
                        runtime,
                    )
                    .await.map_err(|_| ()),
                    Err(_) => Err(()),
                };
                let result = match result {
                    Ok(result) => result,
                    Err(_) => {
                        request.complete_fatal();
                        let _ = shutdown_tx.send(true);
                        let _ = session_import_shutdown_tx.send(true);
                        drop(dispatch);
                        let ingest_result = ingest_task.await;
                        recovery_action_service.shutdown_and_drain().await;
                        task.await??;
                        background_scheduler_task.await??;
                        if let Some(handle) = writer_handle.take() { let _ = handle.shutdown().await; }
                        let _ = (&mut writer_task).await;
                        ingest_result??;
                        return Err("writer failed to reopen after backup".into());
                    }
                };
                recall_worker = spawn_recall_worker_with_config(
                    writer_handle
                        .as_ref()
                        .ok_or("writer unavailable after backup")?
                        .clone(),
                    runtime_snapshot.clone(),
                    data_dir.clone(),
                    Some(Arc::clone(&config_reload)),
                    Some(Arc::clone(&current_session_catalog_report)),
                );
                if !recovery_action_service.resume_after_quiesce() {
                    maintenance_active.store(false, Ordering::Release);
                    drop(dispatch);
                    return Err("recovery action service failed to resume".into());
                }
                maintenance_active.store(false, Ordering::Release);
                drop(dispatch);
                request.complete(result);
            }
            signal = &mut shutdown_signal => {
                signal?;
                let _ = shutdown_tx.send(true);
                let _ = session_import_shutdown_tx.send(true);
                let ingest_result = ingest_task.await;
                recovery_action_service.shutdown_and_drain().await;
                task.await??;
                background_scheduler_task.await??;
                recall_worker.abort();
                let _ = (&mut recall_worker).await;
                if let Some(handle) = writer_handle.take() {
                    handle.shutdown().await?;
                }
                writer_task.await??;
                ingest_result??;
                tracing::info!(target: "evertrace_lifecycle", "daemon stopped");
                return Ok(());
            }
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

fn map_human_surface(surface: HumanSurface) -> EngineHumanSurface {
    match surface {
        HumanSurface::Inbox => EngineHumanSurface::Inbox,
        HumanSurface::Explorer => EngineHumanSurface::Explorer,
        HumanSurface::System => EngineHumanSurface::System,
    }
}

fn map_human_page(page: evertrace_engine::HumanPage) -> HumanGovernanceResponse {
    HumanGovernanceResponse::Snapshot {
        diagnostics: page.diagnostics.map(|value| Box::new(map_diagnostics(value))),
        frontier: page.frontier,
        status: match page.status {
            evertrace_engine::HumanSnapshotStatus::Ready => HumanSnapshotStatus::Ready,
            evertrace_engine::HumanSnapshotStatus::Degraded => HumanSnapshotStatus::Degraded,
        },
        degraded_reasons: page
            .degraded_reasons
            .into_iter()
            .map(|reason| match reason {
                evertrace_engine::HumanDegradedReason::CurrentJobFailed => {
                    HumanDegradedReason::CurrentJobFailed
                }
            })
            .collect(),
        items: page
            .items
            .into_iter()
            .map(|item| HumanSnapshotItem {
                work_detail: item.work_detail.map(|detail| evertrace_protocol::dto::HumanWorkDetail {
                    canonical_goal: detail.canonical_goal, identity_confidence: detail.identity_confidence,
                    source_refs: detail.source_refs, workstream_goal: detail.workstream_goal,
                    phase: detail.phase, acceptance: detail.acceptance,
                }),
                evidence_detail: item.evidence_detail.map(|detail| evertrace_protocol::dto::HumanEvidenceDetail {
                    source_kind: detail.source_kind, observation_role: detail.observation_role,
                    source_role: detail.source_role, content_trust: detail.content_trust,
                    capture_completeness: detail.capture_completeness,
                    protected_presentation: detail.protected_presentation,
                    protected_length: detail.protected_length, cas_ref: detail.cas_ref,
                }),
                item_kind: if item.proposal.is_some() {
                    HumanItemKind::RevisionProposal
                } else {
                    HumanItemKind::Generic
                },
                proposal: item.proposal.map(|proposal| HumanProposalMetadata {
                    proposal_id: proposal.proposal_id,
                    current_revision_id: proposal.current_revision_id,
                    fingerprint: proposal.fingerprint,
                    target_kind: proposal.target_kind,
                    target_id: proposal.target_id,
                    operation: proposal.operation,
                    base_revision_id: proposal.base_revision_id,
                    source_cohort_refs: proposal.source_cohort_refs,
                    eligibility: proposal.eligibility,
                    status: proposal.status,
                }),
                proposal_review: item.proposal_review.map(|review| HumanProposalReview {
                    proposal: review.proposal,
                    plain_accept_eligible: review.plain_accept_eligible,
                    merge_and_accept_eligible: review.merge_and_accept_eligible,
                    reauthorization: review.reauthorization,
                    capability_coverage: review.capability_coverage,
                }),
                support_detail: item.support_detail.map(
                    |EngineHumanSupportDetail {
                         support_contract_revision_id,
                         successor_ref,
                         validation_revision_id,
                         state,
                         dependency_generation,
                         provenance_degraded,
                         threshold,
                         support_revision_refs,
                         authorization_revision_refs,
                         surviving_support_refs,
                         invalid_or_missing_refs,
                         trigger_refs,
                         initial_replacement_payload,
                         deprecate_available,
                     }| HumanSupportDetail {
                        support_contract_revision_id,
                        successor_ref,
                        validation_revision_id,
                        state,
                        dependency_generation,
                        provenance_degraded,
                        threshold,
                        support_revision_refs,
                        authorization_revision_refs,
                        surviving_support_refs,
                        invalid_or_missing_refs,
                        trigger_refs,
                        initial_replacement_payload,
                        deprecate_available,
                    },
                ),
                competing_detail: item.competing_detail.map(
                    |EngineHumanCompetingDetail {
                         expected_group_revision_id,
                         eligible_attempt_ids,
                     }| HumanCompetingDetail {
                        expected_group_revision_id,
                        eligible_attempt_ids,
                    },
                ),
                forget_preview: item.forget_preview.map(|preview| {
                    let EngineHumanForgetPreview {
                        target,
                        current_revision_id,
                        exact_revision_ids,
                        deletion_generation,
                        shared_source_count,
                        suppressed_source_count,
                        suppression_ref_count,
                        downstream_support_revalidation_count,
                        dependent_procedure_review_hold_count,
                    } = *preview;
                    Box::new(HumanForgetPreview {
                        target,
                        current_revision_id,
                        exact_revision_ids,
                        deletion_generation,
                        shared_source_count,
                        suppressed_source_count,
                        suppression_ref_count,
                        downstream_support_revalidation_count,
                        dependent_procedure_review_hold_count,
                    })
                }),
                repository_purge_preview: item.repository_purge_preview.map(|preview| {
                    let EngineHumanRepositoryPurgePreview {
                        repository_id,
                        repository_revision,
                        deletion_generation,
                        planned_exclusive_cas_count,
                        shared_cas_retained_count,
                        repository_derived_global_dependency_count,
                        affected_session_count,
                        affected_evidence_receipt_capture_count,
                        affected_work_count,
                        affected_atom_count,
                        affected_procedure_count,
                        affected_experiment_run_count,
                        affected_result_evidence_count,
                        affected_artifact_count,
                        affected_recovery_count,
                        affected_recall_derived_count,
                        relationship_only_count,
                        estimated_reclaimable_bytes,
                        blockers,
                        downstream_support_revalidation_count,
                        dependent_procedure_review_hold_count,
                    } = *preview;
                    Box::new(HumanRepositoryPurgePreview {
                        repository_id,
                        repository_revision,
                        deletion_generation,
                        planned_exclusive_cas_count,
                        shared_cas_retained_count,
                        repository_derived_global_dependency_count,
                        affected_session_count,
                        affected_evidence_receipt_capture_count,
                        affected_work_count,
                        affected_atom_count,
                        affected_procedure_count,
                        affected_experiment_run_count,
                        affected_result_evidence_count,
                        affected_artifact_count,
                        affected_recovery_count,
                        affected_recall_derived_count,
                        relationship_only_count,
                        estimated_reclaimable_bytes,
                        blockers,
                        downstream_support_revalidation_count,
                        dependent_procedure_review_hold_count,
                    })
                }),
                negative_review: item
                    .negative_review
                    .map(|review| HumanNegativeReviewMetadata {
                        negative_evidence_id: review.negative_evidence_id,
                        current_review_revision_id: review.current_review_revision_id,
                        status: review.status,
                        available_decisions: review
                            .available_decisions
                            .into_iter()
                            .map(|decision| match decision {
                                EngineHumanNegativeDecision::ResolveAsIneffective => {
                                    NegativeReviewDecision::ResolveAsIneffective
                                }
                                EngineHumanNegativeDecision::DismissAttribution => {
                                    NegativeReviewDecision::DismissAttribution
                                }
                                EngineHumanNegativeDecision::ConfirmHarm => {
                                    NegativeReviewDecision::ConfirmHarm
                                }
                                EngineHumanNegativeDecision::RequestRevision => {
                                    NegativeReviewDecision::RequestRevision
                                }
                            })
                            .collect(),
                    }),
                recovery_detail: item.recovery_detail.map(|detail| match detail {
                    EngineHumanRecoveryDetail::CaptureRequest {
                        request_id,
                        revision_id,
                        repository_id,
                        worktree_id,
                        destructive_class,
                        untracked_scope,
                        status,
                        bundle_id,
                        reason_codes,
                    } => HumanRecoveryDetail::CaptureRequest {
                        request_id,
                        revision_id,
                        repository_id,
                        worktree_id,
                        destructive_class,
                        untracked_scope,
                        status,
                        bundle_id,
                        reason_codes,
                    },
                    EngineHumanRecoveryDetail::Bundle {
                        bundle_id,
                        source_worktree_id,
                        source_snapshot_id,
                        capture_status,
                        ordering_integrity,
                        captured_bytes,
                        tracked_diff_count,
                        tracked_file_count,
                        index_state_count,
                        untracked_file_count,
                        untracked_artifact_count,
                        metadata_artifact_count,
                        config_run_count,
                        attempt_anchor_count,
                        omission_counts,
                    } => HumanRecoveryDetail::Bundle {
                        bundle_id,
                        source_worktree_id,
                        source_snapshot_id,
                        capture_status,
                        ordering_integrity,
                        captured_bytes,
                        tracked_diff_count,
                        tracked_file_count,
                        index_state_count,
                        untracked_file_count,
                        untracked_artifact_count,
                        metadata_artifact_count,
                        config_run_count,
                        attempt_anchor_count,
                        omission_counts: omission_counts
                            .into_iter()
                            .map(|entry| HumanRecoveryOmissionCount {
                                reason: entry.reason,
                                count: entry.count,
                            })
                            .collect(),
                    },
                    EngineHumanRecoveryDetail::Application {
                        application_id,
                        revision_id,
                        bundle_id,
                        target_worktree_id,
                        application_kind,
                        input_delivery_state,
                        status,
                        pre_snapshot_id,
                        post_snapshot_id,
                        selected_input_count,
                        result_count,
                        verifier_count,
                    } => HumanRecoveryDetail::Application {
                        application_id,
                        revision_id,
                        bundle_id,
                        target_worktree_id,
                        application_kind,
                        input_delivery_state,
                        status,
                        pre_snapshot_id,
                        post_snapshot_id,
                        selected_input_count,
                        result_count,
                        verifier_count,
                    },
                }),
                worktree_detail: item.worktree_detail.map(|detail| HumanWorktreeDetail {
                    worktree_id: detail.worktree_id,
                    repository_id: detail.repository_id,
                    kind: detail.kind,
                    lifecycle: detail.lifecycle,
                    registration_state: detail.registration_state,
                    current_snapshot_id: detail.current_snapshot_id,
                }),
                execution_integrity_detail: item.execution_integrity_detail.map(|detail| {
                    match detail {
                        EngineHumanExecutionIntegrityDetail::Lane {
                            execution_lane_id,
                            lane_revision,
                            parent_lane_id,
                            status,
                            terminal_kind,
                            liveness_state,
                            finalized,
                            event_watermark,
                            active_capture_receipt_revision_id,
                            coverage_level,
                            source_coverage,
                            pairing_integrity,
                            payload_integrity,
                            ordering_integrity,
                            reasoning_visibility,
                        } => HumanExecutionIntegrityDetail::Lane {
                            execution_lane_id,
                            lane_revision,
                            parent_lane_id,
                            status,
                            terminal_kind,
                            liveness_state,
                            finalized,
                            event_watermark,
                            active_capture_receipt_revision_id,
                            coverage_level,
                            source_coverage,
                            pairing_integrity,
                            payload_integrity,
                            ordering_integrity,
                            reasoning_visibility,
                        },
                        EngineHumanExecutionIntegrityDetail::Receipt {
                            capture_receipt_revision_id,
                            execution_lane_id,
                            predecessor_revision_id,
                            admission_failure_observability,
                            identity_strength,
                            delegation_start_seen,
                            child_session_linked,
                            parent_session_end_seen,
                            lifecycle_end_seen,
                            terminal_event_kind,
                            finalized,
                            first_sequence,
                            last_sequence,
                            sequence_gap_count,
                            outage_count,
                            tool_call_count,
                            tool_result_count,
                            unmatched_tool_call_count,
                            unmatched_tool_result_count,
                            truncation_count,
                            redaction_count,
                            corrupt_count,
                            unsupported_count,
                            import_watermark,
                            coverage_level,
                            source_coverage,
                            pairing_integrity,
                            payload_integrity,
                            ordering_integrity,
                            reasoning_visibility,
                            exact_byte_replay,
                            resolver_version,
                        } => HumanExecutionIntegrityDetail::Receipt {
                            capture_receipt_revision_id,
                            execution_lane_id,
                            predecessor_revision_id,
                            admission_failure_observability,
                            identity_strength,
                            delegation_start_seen,
                            child_session_linked,
                            parent_session_end_seen,
                            lifecycle_end_seen,
                            terminal_event_kind,
                            finalized,
                            first_sequence,
                            last_sequence,
                            sequence_gap_count,
                            outage_count,
                            tool_call_count,
                            tool_result_count,
                            unmatched_tool_call_count,
                            unmatched_tool_result_count,
                            truncation_count,
                            redaction_count,
                            corrupt_count,
                            unsupported_count,
                            import_watermark,
                            coverage_level,
                            source_coverage,
                            pairing_integrity,
                            payload_integrity,
                            ordering_integrity,
                            reasoning_visibility,
                            exact_byte_replay,
                            resolver_version,
                        },
                    }
                }),
                system_detail: item.system_detail.map(|detail| match detail {
                    EngineHumanSystemDetail::Repository { repository_id, repository_revision, user_disabled, trust_revoked, revalidated_inventory_ref, worktree_id } => HumanSystemDetail::Repository { repository_id, repository_revision, user_disabled, trust_revoked, revalidated_inventory_ref, worktree_id },
                    EngineHumanSystemDetail::CapabilityInventory { job_id, repository_id, repository_revision, worktree_id, cwd, state, source_count, signature_count, unobserved_source_count, unknown_contract_count, asset_names } => HumanSystemDetail::CapabilityInventory { job_id, repository_id, repository_revision, worktree_id, cwd, state, source_count, signature_count, unobserved_source_count, unknown_contract_count, asset_names },
                    EngineHumanSystemDetail::SessionImport { session_id, source_instance_id, body_state, access, workspace, repository_read_restrictions } => HumanSystemDetail::SessionImport { session_id, source_instance_id, body_state, access, workspace, repository_read_restrictions },
                    EngineHumanSystemDetail::Job { detail } => {
                        let EngineHumanJobDetail {
                            native_history_cleanup_availability,
                            job_id,
                            target_revision,
                            target_watermark,
                            target_generation,
                            job_kind,
                            algorithm_revision,
                            model_id,
                            priority,
                            state,
                            attempt,
                            backoff_until_us,
                            lease_until_us,
                            config_hash,
                            budget,
                            terminal_reason,
                            terminal_result_ref,
                            backup_summary,
                            gc_report,
                        } = *detail;
                        HumanSystemDetail::Job {
                            detail: Box::new(HumanJobDetail {
                                native_history_cleanup_availability: native_history_cleanup_availability.map(|availability| match availability {
                                    evertrace_engine::HumanNativeHistoryCleanupAvailability::ExternalReaderExclusionUnverified => evertrace_protocol::dto::HumanNativeHistoryCleanupAvailability::ExternalReaderExclusionUnverified,
                                }),
                                job_id,
                                target_revision,
                                target_watermark,
                                target_generation,
                                job_kind,
                                algorithm_revision,
                                model_id,
                                priority,
                                state: match state {
                                    EngineHumanJobState::Queued => HumanJobState::Queued,
                                    EngineHumanJobState::Leased => HumanJobState::Leased,
                                    EngineHumanJobState::Succeeded => HumanJobState::Succeeded,
                                    EngineHumanJobState::Failed => HumanJobState::Failed,
                                },
                                attempt,
                                backoff_until_us,
                                lease_until_us,
                                config_hash,
                                budget: HumanJobBudget {
                                    max_items: budget.max_items,
                                    max_bytes: budget.max_bytes,
                                    max_input_tokens: budget.max_input_tokens,
                                    max_output_tokens: budget.max_output_tokens,
                                    max_calls: budget.max_calls,
                                    max_wall_time_ms: budget.max_wall_time_ms,
                                },
                                terminal_reason: terminal_reason.map(|reason| match reason {
                                    EngineHumanJobTerminalReason::Completed => {
                                        HumanJobTerminalReason::Completed
                                    }
                                    EngineHumanJobTerminalReason::StaleGeneration => {
                                        HumanJobTerminalReason::StaleGeneration
                                    }
                                    EngineHumanJobTerminalReason::BudgetExhausted => {
                                        HumanJobTerminalReason::BudgetExhausted
                                    }
                                    EngineHumanJobTerminalReason::SourceUnavailable => {
                                        HumanJobTerminalReason::SourceUnavailable
                                    }
                                    EngineHumanJobTerminalReason::Unsupported => {
                                        HumanJobTerminalReason::Unsupported
                                    }
                                    EngineHumanJobTerminalReason::SourceReplaced => {
                                        HumanJobTerminalReason::SourceReplaced
                                    }
                                    EngineHumanJobTerminalReason::Revoked => {
                                        HumanJobTerminalReason::Revoked
                                    }
                                    EngineHumanJobTerminalReason::IntegrityFailure => {
                                        HumanJobTerminalReason::IntegrityFailure
                                    }
                                }),
                                terminal_result_ref,
                                backup_summary: backup_summary.map(map_human_backup_summary),
                                gc_summary: gc_report.map(|report| evertrace_protocol::dto::HumanGcSummary {
                                    examined_files: report.examined_files as u32,
                                    marked_candidates: report.marked_candidates as u32,
                                    deleted_count: report.deleted_count() as u32,
                                    deleted_bytes: report.deleted_bytes(),
                                    unknown_count: report.unknown_count() as u32,
                                    mark_watermark: report.mark_watermark,
                                    sweep_watermark: report.sweep_watermark,
                                    checksum: report.checksum,
                                    conservative_prune: report.conservative_prune.into_iter().map(|result| evertrace_protocol::dto::HumanConservativePruneResult {
                                        table: result.table, bytes_removed: result.bytes_removed, old_versions: result.old_versions,
                                    }).collect(),
                                }),
                            }),
                        }
                    }
                    EngineHumanSystemDetail::Config {
                        config_version,
                        effective_config_hash,
                        reload,
                    } => HumanSystemDetail::Config {
                        config_version,
                        effective_config_hash,
                        reload: reload.map(|detail| evertrace_protocol::dto::ConfigReloadAudit {
                            previous_config_hash: detail.previous_config_hash,
                            actor: detail.actor,
                            source: match detail.source {
                                evertrace_engine::ConfigReloadSource::Startup => evertrace_protocol::dto::ConfigReloadSource::Startup,
                                evertrace_engine::ConfigReloadSource::Watcher => evertrace_protocol::dto::ConfigReloadSource::Watcher,
                                evertrace_engine::ConfigReloadSource::Cli => evertrace_protocol::dto::ConfigReloadSource::Cli,
                                evertrace_engine::ConfigReloadSource::Tui => evertrace_protocol::dto::ConfigReloadSource::Tui,
                            },
                            outcome: match detail.outcome {
                                evertrace_engine::ConfigReloadOutcome::Prepared => evertrace_protocol::dto::ConfigReloadOutcome::Prepared,
                                evertrace_engine::ConfigReloadOutcome::Applied => evertrace_protocol::dto::ConfigReloadOutcome::Applied,
                                evertrace_engine::ConfigReloadOutcome::Rejected => evertrace_protocol::dto::ConfigReloadOutcome::Rejected,
                                evertrace_engine::ConfigReloadOutcome::RestartRequired => evertrace_protocol::dto::ConfigReloadOutcome::RestartRequired,
                            },
                        }),
                    },
                }),
                stable_key: item.stable_key,
                row_class: map_human_row_class(item.row_class),
                family: map_human_object_family(item.family),
                category: map_human_item_category(item.category),
                object_kind: item.object_kind,
                object_ref: item.object_ref,
                revision_ref: item.revision_ref,
                lifecycle: item.lifecycle,
                epistemic: item.epistemic,
                authority: item.authority,
                publication_state: item.publication_state,
                support_state: item.support_state,
                scope_ref: item.scope_ref,
                source_event_seq: item.source_event_seq,
            })
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn map_diagnostics(
    value: evertrace_engine::HumanDiagnostics,
) -> evertrace_protocol::dto::HumanDiagnostics {
    use evertrace_engine::HumanDiagnosticState as S;
    use evertrace_protocol::dto::{
        HumanDiagnosticCheck, HumanDiagnosticState as T, HumanDiagnostics, HumanTableDiagnostic,
    };
    HumanDiagnostics {
        config_version: value.config_version,
        algorithm_revision: value.algorithm_revision,
        config_hash: value.config_hash,
        observed_at_us: value.observed_at_us,
        tables: value
            .tables
            .into_iter()
            .map(|table| HumanTableDiagnostic {
                schema_matches: table.schema_matches,
                version: table.version,
                checkpoint: table.checkpoint,
            })
            .collect(),
        checks: value
            .checks
            .into_iter()
            .map(|check| HumanDiagnosticCheck {
                name: check.name.to_owned(),
                state: match check.state {
                    S::Checked => T::Checked,
                    S::Unavailable => T::Unavailable,
                    S::Inconsistent => T::Inconsistent,
                    S::NotChecked => T::NotChecked,
                    S::NotRun => T::NotRun,
                    S::Disabled => T::Disabled,
                    S::Exhausted => T::Exhausted,
                    S::Historical => T::Historical,
                },
                count: check.count,
                limit: check.limit,
            })
            .collect(),
        host: value.host.map(map_host_canary),
    }
}

fn map_human_backup_summary(value: EngineHumanBackupSummary) -> HumanBackupSummary {
    let table = |state: evertrace_engine::HumanBackupTableState| HumanBackupTableState {
        version: state.version,
        frontier: state.frontier,
    };
    HumanBackupSummary {
        frontier: value.frontier,
        journal: table(value.journal),
        objects: table(value.objects),
        relations: value.relations.map(table),
        search: value.search.map(table),
        committed_source_watermark_count: value.committed_source_watermark_count,
        spool_source_watermark_count: value.spool_source_watermark_count,
        live_cas_count: value.live_cas_count,
        spool_cas_count: value.spool_cas_count,
        spool_file_count: value.spool_file_count,
        spool_generation_count: value.spool_generation_count,
        normal_spool_frame_count: value.normal_spool_frame_count,
        isolated_spool_frame_count: value.isolated_spool_frame_count,
        emergency_gap_count: value.emergency_gap_count,
        quarantine_count: value.quarantine_count,
        runtime_outbox_watermark: value.runtime_outbox_watermark,
        index_generation: value.index_generation,
        compiler_watermark: value.compiler_watermark,
        effective_config_hash: value.effective_config_hash,
        runtime_generation: value.runtime_generation,
        hook_current_generation: value.hook_current_generation,
        hook_retained_generations: value.hook_retained_generations,
        hook_pin_count: value.hook_pin_count,
        session_pinned_hook_artifact_count: value.session_pinned_hook_artifact_count,
        object_deletion_generation: value.object_deletion_generation,
        repository_purge_generation: value.repository_purge_generation,
        file_count: value.file_count,
        total_bytes: value.total_bytes,
        required_space_bytes: value.required_space_bytes,
        available_space_bytes_at_preflight: value.available_space_bytes_at_preflight,
        validation_result: match value.validation_result {
            EngineHumanBackupValidationResult::VerifiedBeforePublish => {
                HumanBackupValidationResult::VerifiedBeforePublish
            }
            EngineHumanBackupValidationResult::VerifyJobPassed => {
                HumanBackupValidationResult::VerifyJobPassed
            }
        },
    }
}

fn map_human_row_class(value: EngineHumanRowClass) -> HumanRowClass {
    match value {
        EngineHumanRowClass::Object => HumanRowClass::Object,
        EngineHumanRowClass::Runtime => HumanRowClass::Runtime,
        EngineHumanRowClass::Projection => HumanRowClass::Projection,
    }
}

fn map_human_object_family(value: EngineHumanObjectFamily) -> HumanObjectFamily {
    match value {
        EngineHumanObjectFamily::Evidence => HumanObjectFamily::Evidence,
        EngineHumanObjectFamily::Work => HumanObjectFamily::Work,
        EngineHumanObjectFamily::Atom => HumanObjectFamily::Atom,
        EngineHumanObjectFamily::Procedure => HumanObjectFamily::Procedure,
        EngineHumanObjectFamily::RevisionProposal => HumanObjectFamily::RevisionProposal,
        EngineHumanObjectFamily::Runtime => HumanObjectFamily::Runtime,
        EngineHumanObjectFamily::Projection => HumanObjectFamily::Projection,
    }
}

fn map_human_item_category(value: EngineHumanItemCategory) -> HumanItemCategory {
    match value {
        EngineHumanItemCategory::Proposal => HumanItemCategory::Proposal,
        EngineHumanItemCategory::Support => HumanItemCategory::Support,
        EngineHumanItemCategory::NegativeReview => HumanItemCategory::NegativeReview,
        EngineHumanItemCategory::SegmentationCorrection => {
            HumanItemCategory::SegmentationCorrection
        }
        EngineHumanItemCategory::RecoveryCorrection => HumanItemCategory::RecoveryCorrection,
        EngineHumanItemCategory::Assignment => HumanItemCategory::Assignment,
        EngineHumanItemCategory::CompetingResolution => HumanItemCategory::CompetingResolution,
        EngineHumanItemCategory::AttemptResume => HumanItemCategory::AttemptResume,
        EngineHumanItemCategory::LaneLifecycle => HumanItemCategory::LaneLifecycle,
        EngineHumanItemCategory::CaptureIntegrity => HumanItemCategory::CaptureIntegrity,
        EngineHumanItemCategory::WorktreeLineage => HumanItemCategory::WorktreeLineage,
        EngineHumanItemCategory::ReviewHold => HumanItemCategory::ReviewHold,
        EngineHumanItemCategory::Repository => HumanItemCategory::Repository,
        EngineHumanItemCategory::Work => HumanItemCategory::Work,
        EngineHumanItemCategory::Semantic => HumanItemCategory::Semantic,
        EngineHumanItemCategory::Procedure => HumanItemCategory::Procedure,
        EngineHumanItemCategory::Research => HumanItemCategory::Research,
        EngineHumanItemCategory::RecoveryEvidence => HumanItemCategory::RecoveryEvidence,
        EngineHumanItemCategory::Evidence => HumanItemCategory::Evidence,
        EngineHumanItemCategory::Runtime => HumanItemCategory::Runtime,
        EngineHumanItemCategory::Projection => HumanItemCategory::Projection,
        EngineHumanItemCategory::SessionImport => HumanItemCategory::SessionImport,
        EngineHumanItemCategory::SemanticDerivation => HumanItemCategory::SemanticDerivation,
    }
}

fn map_human_action(outcome: EngineHumanActionOutcome) -> HumanActionResult {
    match outcome {
        EngineHumanActionOutcome::Applied {
            current_revision_ref,
            audit_event_ref,
        } => HumanActionResult {
            status: HumanActionStatus::Applied,
            current_revision_ref: Some(current_revision_ref),
            audit_event_ref: Some(audit_event_ref),
            reason: None,
        },
        EngineHumanActionOutcome::NoDelta {
            current_revision_ref,
        } => HumanActionResult {
            status: HumanActionStatus::NoDelta,
            current_revision_ref: Some(current_revision_ref),
            audit_event_ref: None,
            reason: None,
        },
        EngineHumanActionOutcome::Conflict {
            current_revision_ref,
        } => HumanActionResult {
            status: HumanActionStatus::Conflict,
            current_revision_ref,
            audit_event_ref: None,
            reason: Some("optimistic_conflict".into()),
        },
        EngineHumanActionOutcome::Unavailable { reason } => HumanActionResult {
            status: HumanActionStatus::Unavailable,
            current_revision_ref: None,
            audit_event_ref: None,
            reason: Some(reason.into()),
        },
    }
}

fn map_human_error(error: HumanGovernanceError) -> ErrorCode {
    match error {
        HumanGovernanceError::InvalidInput => ErrorCode::InvalidInput,
        HumanGovernanceError::Store => ErrorCode::Internal,
    }
}

struct StartupArgs {
    config: Option<PathBuf>,
    maintenance: bool,
    candidate: Option<(String, u64)>,
}

impl StartupArgs {
    fn parse() -> Result<Self, &'static str> {
        let mut values = env::args_os().skip(1);
        let mut config = None;
        let mut maintenance = false;
        let mut candidate = None;
        while let Some(value) = values.next() {
            if value == "--config" && config.is_none() {
                config = Some(PathBuf::from(
                    values.next().ok_or("--config requires a path")?,
                ));
            } else if value == "--candidate-check" && candidate.is_none() {
                let id = values
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("candidate id required")?;
                let generation = values
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
                    .filter(|value| *value > 0)
                    .ok_or("candidate generation required")?;
                if id.len() > 128 {
                    return Err("invalid candidate id");
                }
                candidate = Some((id, generation));
            } else if value == "--maintenance" && !maintenance {
                maintenance = true;
            } else {
                return Err("usage: evertraced [--config PATH] [--maintenance]");
            }
        }
        if candidate.is_some() && (maintenance || config.is_none()) {
            return Err("candidate requires explicit config and normal runtime");
        }
        Ok(Self {
            config,
            maintenance,
            candidate,
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
    default_config_path().ok_or("HOME unavailable for default EverTrace configuration")
}

fn default_config_path() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| PathBuf::from(home).join(".evertrace/config.toml"))
}

fn wait_for_signal()
-> Result<impl std::future::Future<Output = Result<(), std::io::Error>>, std::io::Error> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    Ok(async move {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = interrupt.recv() => Ok(()),
                _ = terminate.recv() => Ok(()),
            }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    })
}

#[cfg(all(test, unix))]
mod shutdown_tests {
    #[tokio::test]
    async fn termination_is_retained_while_another_branch_is_awaiting() {
        let mut delivered =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let interrupted_select = super::wait_for_signal().unwrap();
        drop(interrupted_select);
        assert!(
            std::process::Command::new("/usr/bin/kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        delivered.recv().await.unwrap();
        // Re-registering after a selected branch finishes cannot recover TERM.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                super::wait_for_signal().unwrap(),
            )
            .await
            .is_err()
        );
        let signal = super::wait_for_signal().unwrap();
        // A maintenance branch can await without polling the signal future.
        // Its registered receiver must retain TERM throughout that interval.
        assert!(
            std::process::Command::new("/usr/bin/kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        delivered.recv().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), signal)
            .await
            .expect("TERM received during maintenance must not be lost")
            .unwrap();
    }
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
