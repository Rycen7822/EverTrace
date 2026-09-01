#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{env, fs, path::PathBuf, sync::Arc};

use evertrace_engine::{
    BackgroundScheduler, EngineService, HealthDispatchError,
    HumanActionOutcome as EngineHumanActionOutcome,
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
    RuntimeMode, SessionImportWorker, SynthesisPlanner, open_writer, publish_recovery_runtime,
    recall::spawn_recall_worker,
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
use tokio::sync::{RwLock, watch};

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
    let current_session_catalog_report = Arc::new(RwLock::new(None));
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
    );
    human_governance.reconcile_reserved_once().await?;
    let (session_import_wakeup_tx, session_import_wakeup_rx) = watch::channel(0_u64);
    let (session_import_shutdown_tx, session_import_shutdown_rx) = watch::channel(false);
    let scheduler = BackgroundScheduler::new(
        writer_handle.clone(),
        session_catalog,
        session_import_worker,
        Arc::clone(&current_session_catalog_report),
        runtime_snapshot.clone(),
        SynthesisPlanner::new(engine.effective_config().config().llm.clone()),
        engine.effective_config().config().dreaming.clone(),
    );
    let mut background_scheduler_task =
        tokio::spawn(scheduler.run(session_import_wakeup_rx, session_import_shutdown_rx));
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
    let handler_session_catalog_report = Arc::clone(&current_session_catalog_report);
    let handler_session_import_admin = session_import_admin;
    let handler_human_governance = human_governance;
    let handler_session_import_wakeup = session_import_wakeup_tx.clone();
    let mut task = tokio::spawn(server.run_dispatch_with_context(
        shutdown_rx,
        move |context, request_id, command| {
            let handler_engine = Arc::clone(&handler_engine);
            let recovery_service = recovery_service.clone();
            let recovery_action_service = handler_recovery_action_service.clone();
            let mcp_bindings = handler_mcp_bindings.clone();
            let mcp_service = handler_mcp_service.clone();
            let recall_cue_service = recall_cue_service.clone();
            let session_catalog_report = Arc::clone(&handler_session_catalog_report);
            let session_import_admin = handler_session_import_admin.clone();
            let human_governance = handler_human_governance.clone();
            let session_import_wakeup = handler_session_import_wakeup.clone();
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
                        )
                        .ok();
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
                        *session_catalog_report.write().await = observed;
                        let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                        session_import_wakeup.send_replace(next);
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
                        if outcome == SessionImportAdminOutcome::Queued {
                            let next = (*session_import_wakeup.borrow()).wrapping_add(1);
                            session_import_wakeup.send_replace(next);
                        }
                        Ok(Response::SessionImportAdmin(match outcome {
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
                            HumanGovernanceRequest::Read { request } => match request {
                                HumanReadRequest::List {
                                    surface,
                                    expected_frontier,
                                    after,
                                    limit,
                                } => match human_governance
                                    .list(
                                        map_human_surface(surface),
                                        expected_frontier,
                                        after.as_deref(),
                                        limit,
                                    )
                                    .await
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
    tokio::select! {
        result = &mut task => {
            let server_result = result;
            let _ = session_import_shutdown_tx.send(true);
            background_scheduler_task.await??;
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
            let _ = session_import_shutdown_tx.send(true);
            background_scheduler_task.await??;
            recovery_action_service.shutdown_and_drain().await;
            recall_worker.abort();
            let _ = (&mut recall_worker).await;
            task.await??;
            result??;
            Err("writer stopped unexpectedly".into())
        }
        result = &mut recall_worker => {
            let _ = shutdown_tx.send(true);
            let _ = session_import_shutdown_tx.send(true);
            background_scheduler_task.await??;
            recovery_action_service.shutdown_and_drain().await;
            task.await??;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            result?;
            Err("recall worker stopped unexpectedly".into())
        }
        result = &mut background_scheduler_task => {
            let _ = shutdown_tx.send(true);
            recovery_action_service.shutdown_and_drain().await;
            task.await??;
            recall_worker.abort();
            let _ = (&mut recall_worker).await;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            result??;
            Err("background scheduler stopped unexpectedly".into())
        }
        signal = wait_for_signal() => {
            signal?;
            let _ = shutdown_tx.send(true);
            let _ = session_import_shutdown_tx.send(true);
            recovery_action_service.shutdown_and_drain().await;
            task.await??;
            background_scheduler_task.await??;
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

fn map_human_surface(surface: HumanSurface) -> EngineHumanSurface {
    match surface {
        HumanSurface::Inbox => EngineHumanSurface::Inbox,
        HumanSurface::Explorer => EngineHumanSurface::Explorer,
        HumanSurface::System => EngineHumanSurface::System,
    }
}

fn map_human_page(page: evertrace_engine::HumanPage) -> HumanGovernanceResponse {
    HumanGovernanceResponse::Snapshot {
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
                    EngineHumanSystemDetail::Job { detail } => {
                        let EngineHumanJobDetail {
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
                        } = *detail;
                        HumanSystemDetail::Job {
                            detail: Box::new(HumanJobDetail {
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
                            }),
                        }
                    }
                    EngineHumanSystemDetail::Config {
                        config_version,
                        effective_config_hash,
                    } => HumanSystemDetail::Config {
                        config_version,
                        effective_config_hash,
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
