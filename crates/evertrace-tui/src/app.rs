use crate::{
    AppEvent, AppEventSender, AppState, ConnectionState, UiCommand, app_event::HumanReadLocator,
    client, components, keymap, layout, views,
};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame, Terminal, backend::CrosstermBackend, layout::Rect, style::Style, widgets::Paragraph,
};
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct App {
    state: AppState,
}

const MAX_PROPOSAL_EDIT_DOCUMENT: usize = evertrace_protocol::dto::MAX_FRAME_SIZE / 2;

impl App {
    pub fn new() -> Self {
        Self {
            state: AppState::default(),
        }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn handle(&mut self, event: AppEvent) -> UiCommand {
        match event {
            AppEvent::Key(key) if self.state.proposal_edit.is_some() => {
                self.handle_proposal_edit_key(key)
            }
            AppEvent::Key(key) => self.dispatch(keymap::command(key)),
            AppEvent::Health(health) => {
                self.state.shell.health = Some(health);
                self.state.shell.connection = ConnectionState::Connected;
                self.state.proposal_edit = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
                UiCommand::Refresh
            }
            AppEvent::HumanRead {
                surface,
                locator,
                response: snapshot,
            } => {
                let related = matches!(locator, HumanReadLocator::Related { .. });
                if related {
                    if !related_locator_matches(&self.state, &locator) {
                        return UiCommand::None;
                    }
                } else if surface != human_surface(self.state.route) {
                    return UiCommand::None;
                }
                if matches!(locator, HumanReadLocator::Detail { .. })
                    && !detail_locator_matches(&self.state, &locator)
                {
                    return UiCommand::None;
                }
                self.state.proposal_edit = None;
                use evertrace_protocol::dto::HumanGovernanceResponse;
                match (locator, snapshot) {
                    (
                        HumanReadLocator::Related { .. },
                        snapshot @ HumanGovernanceResponse::Snapshot { .. },
                    ) => {
                        let item_count = match &snapshot {
                            HumanGovernanceResponse::Snapshot { items, .. } => items.len(),
                            _ => 0,
                        };
                        self.state.route = crate::Route::Explorer;
                        self.state.selection = 0;
                        self.state.human = Some(snapshot);
                        self.state.detail = None;
                        self.state.detail_message =
                            (item_count == 0).then(|| "no_current_related_rows".into());
                        self.state.detail_scroll = 0;
                        self.state.proposal_confirmation = None;
                        self.state.competing_candidate_selection = 0;
                        self.state.read_conflict = None;
                        UiCommand::None
                    }
                    (
                        HumanReadLocator::List,
                        snapshot @ HumanGovernanceResponse::Snapshot { .. },
                    ) => {
                        let item_count = match &snapshot {
                            HumanGovernanceResponse::Snapshot { items, .. } => items.len(),
                            _ => 0,
                        };
                        self.state.selection =
                            self.state.selection.min(item_count.saturating_sub(1));
                        self.state.human = Some(snapshot);
                        self.state.detail = None;
                        self.state.detail_message = None;
                        self.state.detail_scroll = 0;
                        self.state.proposal_confirmation = None;
                        self.state.competing_candidate_selection = 0;
                        self.state.read_conflict = None;
                        UiCommand::None
                    }
                    (
                        HumanReadLocator::Detail { .. },
                        HumanGovernanceResponse::Snapshot { mut items, .. },
                    ) => {
                        self.state.detail = items.pop();
                        self.state.competing_candidate_selection = 0;
                        self.state.detail_scroll = 0;
                        self.state.detail_message = self
                            .state
                            .detail
                            .is_none()
                            .then(|| "detail_not_found".into());
                        self.state.read_conflict = None;
                        UiCommand::None
                    }
                    (
                        HumanReadLocator::Related { .. },
                        HumanGovernanceResponse::Conflict {
                            current_frontier, ..
                        },
                    ) => {
                        self.state.related_context = None;
                        self.state.human = None;
                        self.state.detail = None;
                        self.state.detail_message = None;
                        self.state.detail_scroll = 0;
                        self.state.selection = 0;
                        self.state.read_conflict = Some(current_frontier);
                        UiCommand::Refresh
                    }
                    (
                        HumanReadLocator::List,
                        HumanGovernanceResponse::Conflict {
                            current_frontier, ..
                        },
                    ) => {
                        self.state.human = None;
                        self.state.detail = None;
                        self.state.detail_message = None;
                        self.state.detail_scroll = 0;
                        self.state.proposal_confirmation = None;
                        self.state.selection = 0;
                        self.state.read_conflict = Some(current_frontier);
                        UiCommand::Refresh
                    }
                    (
                        HumanReadLocator::Detail { .. },
                        HumanGovernanceResponse::Conflict {
                            current_frontier,
                            current_revision_ref,
                        },
                    ) => {
                        self.state.detail = None;
                        self.state.detail_scroll = 0;
                        self.state.proposal_confirmation = None;
                        self.state.read_conflict = Some(current_frontier);
                        self.state.detail_message = Some(current_revision_ref.map_or_else(
                            || format!("detail_conflict frontier {current_frontier}"),
                            |revision| {
                                format!(
                                    "detail_conflict frontier {current_frontier} revision {revision}"
                                )
                            },
                        ));
                        UiCommand::None
                    }
                    (_, HumanGovernanceResponse::Action { .. }) => UiCommand::None,
                }
            }
            AppEvent::HumanAction(response) => {
                use evertrace_protocol::dto::{
                    HumanActionResult, HumanActionStatus, HumanGovernanceResponse,
                };
                let result = match response {
                    HumanGovernanceResponse::Action { result } => result,
                    HumanGovernanceResponse::Conflict {
                        current_revision_ref,
                        ..
                    } => HumanActionResult {
                        status: HumanActionStatus::Conflict,
                        current_revision_ref,
                        audit_event_ref: None,
                        reason: Some("optimistic_conflict".into()),
                    },
                    HumanGovernanceResponse::Snapshot { .. } => return UiCommand::None,
                };
                if result.reason.as_deref() != Some("local_busy") {
                    self.state.write_queued = false;
                }
                self.state.proposal_edit = None;
                self.state.proposal_confirmation = None;
                self.state.competing_candidate_selection = 0;
                self.state.related_context = None;
                self.state.detail = None;
                self.state.detail_scroll = 0;
                let reload = result.status != HumanActionStatus::Unavailable;
                self.state.last_action = Some(result);
                if reload {
                    UiCommand::Refresh
                } else {
                    UiCommand::None
                }
            }
            AppEvent::Recovery(response) => {
                self.state.write_queued = false;
                self.state.proposal_edit = None;
                self.state.recovery_selection = None;
                self.state.recovery_confirmation = None;
                self.state.related_context = None;
                self.state.recovery_result = Some(response);
                UiCommand::None
            }
            AppEvent::Pending(count) => {
                self.state.shell.pending = count;
                UiCommand::None
            }
            AppEvent::Disconnected => {
                self.state.shell.connection = ConnectionState::Disconnected;
                self.state.proposal_edit = None;
                self.state.write_queued = false;
                self.state.proposal_confirmation = None;
                self.state.detail = None;
                self.state.detail_scroll = 0;
                self.state.recovery_selection = None;
                self.state.recovery_confirmation = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
                UiCommand::None
            }
            AppEvent::Notification(_) => {
                self.state.shell.connection = ConnectionState::ServerStopping;
                self.state.proposal_edit = None;
                self.state.proposal_confirmation = None;
                self.state.detail = None;
                self.state.detail_scroll = 0;
                self.state.recovery_selection = None;
                self.state.recovery_confirmation = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
                UiCommand::None
            }
            AppEvent::Shutdown => self.dispatch(UiCommand::Quit),
            AppEvent::Tick | AppEvent::Resize(_, _) => UiCommand::None,
        }
    }

    fn handle_proposal_edit_key(&mut self, key: KeyEvent) -> UiCommand {
        if key.code == KeyCode::Esc {
            self.state.proposal_edit = None;
            return UiCommand::None;
        }
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            submit_proposal_edit(&mut self.state);
            return UiCommand::None;
        }
        let Some(edit) = self.state.proposal_edit.as_mut() else {
            return UiCommand::None;
        };
        let changed = match key.code {
            KeyCode::Char(value) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                insert_edit_text(edit, value.encode_utf8(&mut [0; 4]))
            }
            KeyCode::Enter => insert_edit_text(edit, "\n"),
            KeyCode::Backspace => delete_edit_previous(edit),
            KeyCode::Delete => delete_edit_next(edit),
            KeyCode::Left => {
                edit.cursor = previous_char_boundary(&edit.document, edit.cursor);
                false
            }
            KeyCode::Right => {
                edit.cursor = next_char_boundary(&edit.document, edit.cursor);
                false
            }
            KeyCode::Home => {
                edit.cursor = edit.document[..edit.cursor]
                    .rfind('\n')
                    .map_or(0, |index| index + 1);
                false
            }
            KeyCode::End => {
                edit.cursor = edit.document[edit.cursor..]
                    .find('\n')
                    .map_or(edit.document.len(), |index| edit.cursor + index);
                false
            }
            KeyCode::Up => {
                move_edit_vertical(edit, false);
                false
            }
            KeyCode::Down => {
                move_edit_vertical(edit, true);
                false
            }
            _ => false,
        };
        if changed {
            edit.error = None;
        }
        UiCommand::None
    }

    pub fn dispatch(&mut self, command: UiCommand) -> UiCommand {
        if self.state.future_operation_shell.is_some()
            && !matches!(
                command,
                UiCommand::CancelModal
                    | UiCommand::Navigate(_)
                    | UiCommand::Refresh
                    | UiCommand::Quit
            )
        {
            return UiCommand::None;
        }
        match command {
            UiCommand::Navigate(route) => {
                self.state.route = route;
                self.state.human = None;
                self.state.detail = None;
                self.state.detail_message = None;
                self.state.detail_scroll = 0;
                self.state.selection = 0;
                self.state.proposal_confirmation = None;
                self.state.competing_candidate_selection = 0;
                self.state.proposal_edit = None;
                self.state.recovery_selection = None;
                self.state.recovery_confirmation = None;
                self.state.read_conflict = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
            }
            UiCommand::Quit => self.state.quit = true,
            UiCommand::OpenProposalEditor => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                } else {
                    match proposal_edit_state(&self.state) {
                        Ok(edit) => {
                            self.state.proposal_edit = Some(edit);
                            self.state.proposal_confirmation = None;
                            self.state.last_action = None;
                        }
                        Err(reason) => {
                            self.state.last_action = Some(local_unavailable(reason));
                        }
                    }
                }
            }
            UiCommand::OpenSupportDeprecateEditor => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                } else {
                    match support_deprecate_edit_state(&self.state) {
                        Ok(edit) => {
                            self.state.proposal_edit = Some(edit);
                            self.state.proposal_confirmation = None;
                            self.state.last_action = None;
                        }
                        Err(reason) => {
                            self.state.last_action = Some(local_unavailable(reason));
                        }
                    }
                }
            }
            UiCommand::PrepareRecovery(kind) => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                } else if let Some(recovery_bundle_id) = selected_recovery_bundle(&self.state) {
                    self.state.recovery_selection = Some(crate::state::RecoverySelection {
                        recovery_bundle_id,
                        application_kind: kind,
                    });
                    self.state.recovery_confirmation = None;
                    self.state.last_action = None;
                } else {
                    self.state.last_action =
                        Some(local_unavailable("select_recovery_bundle_first"));
                }
            }
            UiCommand::CancelModal => {
                let dismissed_edit = self.state.proposal_edit.take().is_some();
                let dismissed_future = self.state.future_operation_shell.take().is_some();
                if dismissed_edit || dismissed_future {
                    self.state.detail_scroll = 0;
                } else if self.state.recovery_confirmation.is_some()
                    || self.state.proposal_confirmation.is_some()
                    || self.state.recovery_selection.is_some()
                {
                    self.state.recovery_selection = None;
                    self.state.recovery_confirmation = None;
                    self.state.proposal_confirmation = None;
                    self.state.detail_scroll = 0;
                } else {
                    self.state.detail = None;
                    self.state.detail_message = None;
                    self.state.detail_scroll = 0;
                }
            }
            UiCommand::SelectNext => {
                if self.state.detail.is_some() {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_add(1);
                    return UiCommand::None;
                }
                self.state.detail = None;
                self.state.detail_message = None;
                self.state.proposal_confirmation = None;
                self.state.competing_candidate_selection = 0;
                let last = snapshot_item_count(&self.state).saturating_sub(1);
                self.state.selection = self.state.selection.saturating_add(1).min(last);
            }
            UiCommand::SelectPrevious => {
                if self.state.detail.is_some() {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_sub(1);
                    return UiCommand::None;
                }
                self.state.detail = None;
                self.state.detail_message = None;
                self.state.proposal_confirmation = None;
                self.state.competing_candidate_selection = 0;
                self.state.selection = self.state.selection.saturating_sub(1)
            }
            UiCommand::PrepareProposal(decision) => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = proposal_action(&self.state, decision);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action = Some(local_unavailable(match decision {
                        evertrace_protocol::dto::ProposalHumanDecision::Accept
                        | evertrace_protocol::dto::ProposalHumanDecision::MergeAndAccept => {
                            proposal_action_unavailable_reason(&self.state, decision)
                        }
                        evertrace_protocol::dto::ProposalHumanDecision::EditAndAccept => {
                            "atomic_edit_and_accept_unavailable"
                        }
                        evertrace_protocol::dto::ProposalHumanDecision::Defer
                        | evertrace_protocol::dto::ProposalHumanDecision::Reject => {
                            "select_current_proposal"
                        }
                    }));
                }
            }
            UiCommand::PrepareNegativeReview(decision) => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = negative_review_action(&self.state, decision);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action = Some(evertrace_protocol::dto::HumanActionResult {
                        status: evertrace_protocol::dto::HumanActionStatus::Unavailable,
                        current_revision_ref: None,
                        audit_event_ref: None,
                        reason: Some("negative_review_proof_unavailable".into()),
                    });
                }
            }
            UiCommand::SelectCompetingPrevious => {
                if current_detail(&self.state)
                    .and_then(|item| item.competing_detail.as_ref())
                    .is_some()
                {
                    self.state.competing_candidate_selection =
                        self.state.competing_candidate_selection.saturating_sub(1);
                }
                return UiCommand::None;
            }
            UiCommand::SelectCompetingNext => {
                if let Some(last) = current_detail(&self.state)
                    .and_then(|item| item.competing_detail.as_ref())
                    .map(|detail| detail.eligible_attempt_ids.len().saturating_sub(1))
                {
                    self.state.competing_candidate_selection = self
                        .state
                        .competing_candidate_selection
                        .saturating_add(1)
                        .min(last);
                }
                return UiCommand::None;
            }
            UiCommand::PrepareCompetingSelected => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = competing_selected_action(&self.state);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action =
                        Some(local_unavailable("competing_selected_unavailable"));
                }
            }
            UiCommand::PrepareMarkNewAttempt => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = mark_new_attempt_action(&self.state);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action =
                        Some(local_unavailable("mark_new_attempt_unavailable"));
                }
            }
            UiCommand::OpenRelated => {
                self.state.related_context = related_context(&self.state);
                if self.state.related_context.is_none() {
                    self.state.last_action = Some(local_unavailable("related_source_unavailable"));
                }
            }
            UiCommand::OpenFutureOperationShell => {
                if self.state.proposal_confirmation.is_none()
                    && self.state.recovery_confirmation.is_none()
                    && self.state.recovery_selection.is_none()
                {
                    self.state.future_operation_shell = future_operation_shell(&self.state);
                }
            }
            UiCommand::Detail if self.state.future_operation_shell.is_some() => {
                return UiCommand::None;
            }
            UiCommand::Detail if self.state.recovery_confirmation.is_some() => {
                return UiCommand::ConfirmRecovery;
            }
            UiCommand::Detail if self.state.recovery_selection.is_some() => {
                if let Some(request) = recovery_request(&self.state) {
                    self.state.recovery_selection = None;
                    self.state.recovery_confirmation = Some(request);
                    self.state.last_action = None;
                } else {
                    self.state.last_action =
                        Some(local_unavailable("select_recovery_target_worktree"));
                }
                return UiCommand::None;
            }
            UiCommand::Detail if self.state.proposal_confirmation.is_some() => {
                return UiCommand::ConfirmProposal;
            }
            UiCommand::Refresh => {
                self.state.selection = 0;
                self.state.detail = None;
                self.state.detail_message = None;
                self.state.detail_scroll = 0;
                self.state.proposal_confirmation = None;
                self.state.competing_candidate_selection = 0;
                self.state.proposal_edit = None;
                self.state.recovery_selection = None;
                self.state.recovery_confirmation = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
            }
            UiCommand::NextPage
            | UiCommand::FirstPage
            | UiCommand::Detail
            | UiCommand::ConfirmProposal
            | UiCommand::ConfirmRecovery
            | UiCommand::None => {}
        }
        command
    }

    fn take_recovery_confirmation(
        &mut self,
    ) -> Option<evertrace_protocol::command::RequestRecoveryCommand> {
        self.state.recovery_confirmation.take()
    }

    pub fn render(&self, frame: &mut Frame) {
        let palette = &crate::theme::EVER_OS;
        let shell = layout::shell(frame.area());
        frame.render_widget(
            components::header().style(Style::default().fg(palette.ink).bg(palette.background)),
            shell.header,
        );
        if shell.compact {
            views::render(frame, shell.list, &self.state);
        } else {
            frame.render_widget(components::navigation(self.state.route), shell.nav);
            views::render(frame, shell.list, &self.state);
            frame.render_widget(
                components::inspector(views::inspector_text(&self.state))
                    .style(Style::default().fg(palette.muted).bg(palette.surface))
                    .scroll((self.state.detail_scroll, 0)),
                shell.inspector,
            );
        }
        frame.render_widget(components::status_bar(&self.state.shell), shell.status);
        let hints = if self.state.proposal_edit.is_some() {
            "Closed payload edit: Ctrl+S submit for confirmation; Esc cancels".into()
        } else if self.state.future_operation_shell.is_some() {
            "Esc dismisses; no operation will be sent".into()
        } else if self.state.detail.is_some() || self.state.detail_message.is_some() {
            if future_operation_shell(&self.state).is_some() {
                "Esc back  g future Forget info  o related  j/k scroll  r refresh  q quit".into()
            } else if current_detail(&self.state).is_some_and(|item| {
                item.category == evertrace_protocol::dto::HumanItemCategory::AttemptResume
            }) {
                "Esc back  A mark new attempt  j/k scroll  o related  r refresh  q quit".into()
            } else if current_detail(&self.state).is_some_and(|item| item.support_detail.is_some())
            {
                "Esc back  E replacement  D deprecate  j/k scroll  o related  r refresh  q quit"
                    .into()
            } else {
                "Esc back  j/k scroll  o related  n next page  b first page  r refresh  q quit"
                    .into()
            }
        } else if let Some(selection) = self.state.recovery_selection {
            format!(
                "Bundle {} {:?} selected; select target Worktree, Enter continues, Esc cancels",
                selection.recovery_bundle_id, selection.application_kind
            )
        } else if self.state.route == crate::Route::Explorer {
            "1 Inbox  2 Explorer  3 System  r refresh  p/f/i/M recovery  q quit".into()
        } else if self.state.route == crate::Route::System {
            "1 Inbox  2 Explorer  3 System  g maintenance boundaries  r refresh  q quit".into()
        } else {
            "1 Inbox  2 Explorer  3 System  r refresh  q quit".into()
        };
        frame.render_widget(
            Paragraph::new(hints).style(Style::default().fg(palette.muted)),
            shell.hints,
        );
        if let Some(edit) = &self.state.proposal_edit {
            let area = centered(
                frame.area(),
                76,
                frame.area().height.saturating_sub(2).min(18),
            );
            let (clear, modal) = components::modal(proposal_edit_modal_text(
                edit,
                area.width.saturating_sub(4) as usize,
                area.height.saturating_sub(5) as usize,
            ));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some(operation) = &self.state.future_operation_shell {
            let area = centered(frame.area(), 58, 11);
            let (clear, modal) = components::modal(future_operation_text(operation));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some(request) = &self.state.recovery_confirmation {
            let area = centered(frame.area(), 72, 6);
            let (clear, modal) = components::modal(format!(
                "Bundle: {}\nTarget Worktree: {}\nKind: {:?}\nEnter confirms once; Esc cancels",
                request.recovery_bundle_id,
                request.target_worktree_instance_id,
                request.application_kind,
            ));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some((_, action, review)) = &self.state.proposal_confirmation {
            let area = centered(frame.area(), 72, 6);
            let review_tuple = review.as_ref().map_or_else(
                || "Review: current closed action".into(),
                |review| {
                    format!(
                        "Proposal: {}\nRevision: {}\nFingerprint: {}",
                        review.proposal.proposal_id,
                        review.proposal.proposal_revision_id,
                        evertrace_domain::evidence::hex(&review.proposal.fingerprint)
                    )
                },
            );
            let (clear, modal) = components::modal(format!(
                "Confirm {} once; Esc cancels\n{review_tuple}",
                human_action_label(action)
            ));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if self.state.shell.pending > 0 {
            let area = centered(frame.area(), 28, 3);
            let (clear, modal) = components::modal("Request pending".into());
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        }
    }
}

fn proposal_edit_state(state: &AppState) -> Result<crate::state::ProposalEditState, &'static str> {
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } =
        state.human.as_ref().ok_or("select_current_proposal")?
    else {
        return Err("select_current_proposal");
    };
    let context = if let Some(review) = current_proposal_review(state) {
        if !review.proposal.status.is_open()
            || review.proposal.eligibility
                == evertrace_domain::semantic::ProposalEligibility::AutoEligibleFull
            || !proposal_payload_edit_supported(&review.proposal.payload)
        {
            return Err("atomic_edit_and_accept_unavailable");
        }
        crate::state::ProposalEditContext::Proposal(review.clone())
    } else if let Some(support) =
        current_detail(state).and_then(|item| item.support_detail.as_ref())
        && let Some(initial_payload) = &support.initial_replacement_payload
    {
        crate::state::ProposalEditContext::SupportReplacement {
            expected_validation_revision_id: support.validation_revision_id,
            original_payload: initial_payload.clone(),
        }
    } else {
        return Err("support_replacement_unavailable");
    };
    let original_payload = match &context {
        crate::state::ProposalEditContext::Proposal(review) => &review.proposal.payload,
        crate::state::ProposalEditContext::SupportReplacement {
            original_payload, ..
        }
        | crate::state::ProposalEditContext::SupportDeprecate {
            original_payload, ..
        } => original_payload.as_ref(),
    };
    let document = evertrace_protocol::dto::proposal_payload_pretty_document(original_payload)
        .map_err(|_| "proposal_document_serialize_failed")?;
    if document.len() > MAX_PROPOSAL_EDIT_DOCUMENT {
        return Err("proposal_document_too_large");
    }
    let cursor = document.len();
    Ok(crate::state::ProposalEditState {
        frozen_frontier: *frontier,
        context,
        document,
        cursor,
        error: None,
    })
}

fn support_deprecate_edit_state(
    state: &AppState,
) -> Result<crate::state::ProposalEditState, &'static str> {
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } = state
        .human
        .as_ref()
        .ok_or("support_deprecate_unavailable")?
    else {
        return Err("support_deprecate_unavailable");
    };
    let support = current_detail(state)
        .and_then(|item| item.support_detail.as_ref())
        .filter(|support| support.deprecate_available)
        .ok_or("support_deprecate_unavailable")?;
    let original_payload = Box::new(evertrace_domain::semantic::ProposalPayload::Atom(Box::new(
        evertrace_domain::semantic::AtomProposalPayload::Deprecate {
            reason: String::new(),
        },
    )));
    let document = evertrace_protocol::dto::proposal_payload_pretty_document(&original_payload)
        .map_err(|_| "proposal_document_serialize_failed")?;
    if document.len() > MAX_PROPOSAL_EDIT_DOCUMENT {
        return Err("proposal_document_too_large");
    }
    let cursor = document.len();
    Ok(crate::state::ProposalEditState {
        frozen_frontier: *frontier,
        context: crate::state::ProposalEditContext::SupportDeprecate {
            expected_validation_revision_id: support.validation_revision_id,
            original_payload,
        },
        document,
        cursor,
        error: None,
    })
}

fn proposal_payload_edit_supported(payload: &evertrace_domain::semantic::ProposalPayload) -> bool {
    use evertrace_domain::semantic::{
        AtomProposalPayload, ProcedureProposalPayload, ProposalPayload,
    };
    match payload {
        ProposalPayload::Atom(payload) => matches!(
            payload.as_ref(),
            AtomProposalPayload::Create { .. }
                | AtomProposalPayload::Replace { .. }
                | AtomProposalPayload::Deprecate { .. }
                | AtomProposalPayload::Reclassify { .. }
        ),
        ProposalPayload::Procedure(payload) => matches!(
            payload.as_ref(),
            ProcedureProposalPayload::Create { .. } | ProcedureProposalPayload::Replace { .. }
        ),
        ProposalPayload::CoreMembership(_) | ProposalPayload::ReservedTarget { .. } => false,
    }
}

fn proposal_edit_shape_matches(
    original: &evertrace_domain::semantic::ProposalPayload,
    edited: &evertrace_domain::semantic::ProposalPayload,
) -> bool {
    use evertrace_domain::semantic::{
        AtomProposalPayload, ProcedureProposalPayload, ProposalPayload,
    };
    matches!(
        (original, edited),
        (
            ProposalPayload::Atom(original),
            ProposalPayload::Atom(edited)
        ) if matches!(
            (original.as_ref(), edited.as_ref()),
            (AtomProposalPayload::Create { .. }, AtomProposalPayload::Create { .. })
                | (AtomProposalPayload::Replace { .. }, AtomProposalPayload::Replace { .. })
                | (AtomProposalPayload::Deprecate { .. }, AtomProposalPayload::Deprecate { .. })
                | (
                    AtomProposalPayload::Reclassify { .. },
                    AtomProposalPayload::Reclassify { .. }
                )
        )
    ) || matches!(
        (original, edited),
        (
            ProposalPayload::Procedure(original),
            ProposalPayload::Procedure(edited)
        ) if matches!(
            (original.as_ref(), edited.as_ref()),
            (
                ProcedureProposalPayload::Create { .. },
                ProcedureProposalPayload::Create { .. }
            ) | (
                ProcedureProposalPayload::Replace { .. },
                ProcedureProposalPayload::Replace { .. }
            )
        )
    )
}

fn submit_proposal_edit(state: &mut AppState) {
    let result = state
        .proposal_edit
        .as_ref()
        .ok_or_else(|| "proposal_editor_not_open".to_owned())
        .and_then(|edit| {
            let payload = evertrace_protocol::dto::parse_proposal_payload_document(&edit.document)
                .map_err(|error| format!("parse_error: {error}"))?;
            let original_payload = match &edit.context {
                crate::state::ProposalEditContext::Proposal(review) => &review.proposal.payload,
                crate::state::ProposalEditContext::SupportReplacement {
                    original_payload, ..
                }
                | crate::state::ProposalEditContext::SupportDeprecate {
                    original_payload, ..
                } => original_payload.as_ref(),
            };
            if &payload == original_payload {
                return Err("edited_payload_is_unchanged".into());
            }
            if !proposal_edit_shape_matches(original_payload, &payload) {
                return Err("unsupported_edit_shape".into());
            }
            if matches!(
                edit.context,
                crate::state::ProposalEditContext::SupportDeprecate { .. }
            ) {
                let evertrace_domain::semantic::ProposalPayload::Atom(value) = &payload else {
                    return Err("unsupported_edit_shape".into());
                };
                value
                    .validate()
                    .map_err(|_| "deprecation_reason_required".to_owned())?;
            }
            Ok((edit.frozen_frontier, edit.context.clone(), payload))
        });
    let (frontier, context, payload) = match result {
        Ok(value) => value,
        Err(error) => {
            if let Some(edit) = state.proposal_edit.as_mut() {
                edit.error = Some(error);
            }
            return;
        }
    };
    state.proposal_confirmation = Some(match context {
        crate::state::ProposalEditContext::Proposal(review) => (
            frontier,
            evertrace_protocol::dto::HumanActionRequest::Proposal {
                proposal_id: review.proposal.proposal_id,
                expected_revision_id: review.proposal.proposal_revision_id,
                expected_fingerprint: evertrace_domain::evidence::hex(&review.proposal.fingerprint),
                decision: evertrace_protocol::dto::ProposalHumanDecision::EditAndAccept,
                edited_payload: Some(Box::new(payload)),
            },
            Some(review),
        ),
        crate::state::ProposalEditContext::SupportReplacement {
            expected_validation_revision_id,
            ..
        } => (
            frontier,
            evertrace_protocol::dto::HumanActionRequest::SupportReplacement {
                expected_validation_revision_id,
                edited_payload: Box::new(payload),
            },
            None,
        ),
        crate::state::ProposalEditContext::SupportDeprecate {
            expected_validation_revision_id,
            ..
        } => {
            let evertrace_domain::semantic::ProposalPayload::Atom(payload) = payload else {
                unreachable!("support deprecate shape was validated")
            };
            let evertrace_domain::semantic::AtomProposalPayload::Deprecate { reason } = *payload
            else {
                unreachable!("support deprecate operation was validated")
            };
            (
                frontier,
                evertrace_protocol::dto::HumanActionRequest::SupportDeprecate {
                    expected_validation_revision_id,
                    reason,
                },
                None,
            )
        }
    });
    state.proposal_edit = None;
}

fn insert_edit_text(edit: &mut crate::state::ProposalEditState, value: &str) -> bool {
    if edit.document.len().saturating_add(value.len()) > MAX_PROPOSAL_EDIT_DOCUMENT {
        edit.error = Some("proposal_document_too_large".into());
        return false;
    }
    edit.document.insert_str(edit.cursor, value);
    edit.cursor += value.len();
    true
}

fn delete_edit_previous(edit: &mut crate::state::ProposalEditState) -> bool {
    let previous = previous_char_boundary(&edit.document, edit.cursor);
    if previous == edit.cursor {
        return false;
    }
    edit.document.drain(previous..edit.cursor);
    edit.cursor = previous;
    true
}

fn delete_edit_next(edit: &mut crate::state::ProposalEditState) -> bool {
    let next = next_char_boundary(&edit.document, edit.cursor);
    if next == edit.cursor {
        return false;
    }
    edit.document.drain(edit.cursor..next);
    true
}

fn previous_char_boundary(value: &str, cursor: usize) -> usize {
    value[..cursor]
        .char_indices()
        .next_back()
        .map_or(cursor, |(index, _)| index)
}

fn next_char_boundary(value: &str, cursor: usize) -> usize {
    value[cursor..]
        .chars()
        .next()
        .map_or(cursor, |value| cursor + value.len_utf8())
}

fn move_edit_vertical(edit: &mut crate::state::ProposalEditState, down: bool) {
    let line_start = edit.document[..edit.cursor]
        .rfind('\n')
        .map_or(0, |index| index + 1);
    let line_end = edit.document[edit.cursor..]
        .find('\n')
        .map_or(edit.document.len(), |index| edit.cursor + index);
    let column = edit.document[line_start..edit.cursor].chars().count();
    let (target_start, target_end) = if down {
        if line_end == edit.document.len() {
            return;
        }
        let start = line_end + 1;
        let end = edit.document[start..]
            .find('\n')
            .map_or(edit.document.len(), |index| start + index);
        (start, end)
    } else {
        if line_start == 0 {
            return;
        }
        let end = line_start - 1;
        let start = edit.document[..end]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        (start, end)
    };
    edit.cursor = edit.document[target_start..target_end]
        .char_indices()
        .nth(column)
        .map_or(target_end, |(index, _)| target_start + index);
}

fn proposal_edit_modal_text(
    edit: &crate::state::ProposalEditState,
    width: usize,
    visible_rows: usize,
) -> String {
    let width = width.max(12);
    let visible_rows = visible_rows.max(1);
    let cursor_line = edit.document[..edit.cursor]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let cursor_column = edit.document[..edit.cursor]
        .rsplit_once('\n')
        .map_or(edit.document[..edit.cursor].chars().count(), |(_, line)| {
            line.chars().count()
        });
    let first_line = cursor_line.saturating_sub(visible_rows / 2);
    let mut rendered = String::with_capacity(width.saturating_mul(visible_rows + 4));
    rendered.push_str(match &edit.context {
        crate::state::ProposalEditContext::Proposal(_) => "EDIT PROPOSAL DOCUMENT\n",
        crate::state::ProposalEditContext::SupportReplacement { .. } => {
            "EDIT SUPPORT REPLACEMENT\n"
        }
        crate::state::ProposalEditContext::SupportDeprecate { .. } => {
            "SUBMIT SUPPORT DEPRECATION\n"
        }
    });
    rendered.push_str("Ctrl+S submit  Esc cancel\n");
    rendered.push_str(&format!(
        "line {} column {}  bytes {}/{}\n",
        cursor_line + 1,
        cursor_column + 1,
        edit.document.len(),
        MAX_PROPOSAL_EDIT_DOCUMENT
    ));
    if let Some(error) = &edit.error {
        rendered.push_str("ERROR: ");
        rendered.extend(error.chars().take(width.saturating_sub(7)));
        rendered.push('\n');
    }
    for (line_index, line) in edit
        .document
        .split('\n')
        .enumerate()
        .skip(first_line)
        .take(visible_rows)
    {
        rendered.push_str(if line_index == cursor_line {
            "> "
        } else {
            "  "
        });
        rendered.extend(line.chars().take(width.saturating_sub(2)));
        rendered.push('\n');
    }
    rendered
}

fn future_operation_text(operation: &crate::state::FutureOperationShell) -> String {
    use crate::state::FutureOperationShell;
    match operation {
        FutureOperationShell::ForgetAtom(object_ref) => future_forget_text("Atom", object_ref),
        FutureOperationShell::ForgetProcedure(object_ref) => {
            future_forget_text("Procedure", object_ref)
        }
        FutureOperationShell::ForgetCoreMembership(object_ref) => {
            future_forget_text("Core membership", object_ref)
        }
        FutureOperationShell::Maintenance => [
            "Maintenance is unavailable in this S31 shell.",
            "Repository purge needs a future preview.",
            "Its maintenance flow is also future work.",
            "Backup/verify belongs to S33.",
            "Restore is offline-only.",
            "No restore CLI command is asserted here.",
            "Orphan GC belongs to S33.",
            "No command will be sent.",
            "Esc dismisses.",
        ]
        .join("\n"),
    }
}

fn future_forget_text(kind: &str, object_ref: &str) -> String {
    format!(
        "Forget requires the future S32 domain preview.\nObject kind: {kind}\nObject ID:\n{object_ref}\nObject Forget is not source erasure.\nNo affected counts or closure are available.\nNo space or support estimate is available.\nNo preview hash, token, or job ID exists.\nNo command will be sent."
    )
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

pub fn headless_render(width: u16, height: u16) -> Result<String, io::Error> {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    let app = App::new();
    terminal.draw(|frame| app.render(frame))?;
    let buffer = terminal.backend().buffer();
    let mut lines = (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    Ok(lines.join("\n"))
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn run(socket: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut guard = crate::TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let (events, mut receiver) = AppEventSender::channel();
    let (client_commands, client_receiver) = client::channel();
    let mut client_task = tokio::spawn(client::run(socket, events.clone(), client_receiver));
    let stop = Arc::new(AtomicBool::new(false));
    let input_task = spawn_input(events, stop.clone());
    let ui_commands = client_commands.clone();
    let ui_task = tokio::spawn(async move {
        let mut app = App::new();
        loop {
            terminal.draw(|frame| app.render(frame))?;
            let Some(event) = receiver.recv().await else {
                return Ok::<(), io::Error>(());
            };
            let command = app.handle(event);
            if matches!(command, UiCommand::Refresh | UiCommand::Navigate(_)) {
                let _ = ui_commands.try_send(client::ClientCommand::Refresh(human_surface(
                    app.state.route,
                )));
            }
            if let Some(request) = human_request(&app.state, command) {
                let _ = ui_commands.try_send(client::ClientCommand::Human(request));
            }
            if command == UiCommand::ConfirmRecovery
                && let Some(request) = app.state.recovery_confirmation.clone()
            {
                match ui_commands.try_send(client::ClientCommand::Recovery(request)) {
                    Ok(()) => {
                        let _ = app.take_recovery_confirmation();
                        app.state.write_queued = true;
                    }
                    Err(_) => app.state.last_action = Some(local_transport_error()),
                }
            }
            if command == UiCommand::ConfirmProposal
                && let Some((expected_frontier, action, _)) =
                    app.state.proposal_confirmation.clone()
            {
                match ui_commands.try_send(client::ClientCommand::Human(
                    evertrace_protocol::dto::HumanGovernanceRequest::Act {
                        expected_frontier,
                        action,
                    },
                )) {
                    Ok(()) => {
                        app.state.proposal_confirmation = None;
                        app.state.write_queued = true;
                    }
                    Err(_) => app.state.last_action = Some(local_transport_error()),
                }
            }
            if app.state.quit {
                return Ok(());
            }
        }
    });
    let result: Result<(), Box<dyn std::error::Error>> = match ui_task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Box::new(error)),
        Err(error) => Err(Box::new(error)),
    };

    stop.store(true, Ordering::Release);
    let force_abort = matches!(
        client_commands.try_send(client::ClientCommand::Shutdown),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_))
    );
    let _ = input_task.await;
    let needs_abort = force_abort
        || tokio::time::timeout(Duration::from_secs(1), &mut client_task)
            .await
            .is_err();
    if needs_abort {
        client_task.abort();
        let _ = client_task.await;
    }
    let restore = guard.restore();
    result?;
    restore?;
    Ok(())
}

fn human_surface(route: crate::Route) -> evertrace_protocol::dto::HumanSurface {
    match route {
        crate::Route::Inbox => evertrace_protocol::dto::HumanSurface::Inbox,
        crate::Route::Explorer => evertrace_protocol::dto::HumanSurface::Explorer,
        crate::Route::System => evertrace_protocol::dto::HumanSurface::System,
    }
}

fn selected_item(state: &AppState) -> Option<&evertrace_protocol::dto::HumanSnapshotItem> {
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { items, .. } =
        state.human.as_ref()?
    else {
        return None;
    };
    items.get(state.selection)
}

fn detail_locator_matches(state: &AppState, locator: &HumanReadLocator) -> bool {
    let HumanReadLocator::Detail {
        expected_frontier,
        stable_key,
        expected_revision_ref,
    } = locator
    else {
        return false;
    };
    let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. }) =
        state.human.as_ref()
    else {
        return false;
    };
    let Some(item) = selected_item(state) else {
        return false;
    };
    frontier == expected_frontier
        && item.stable_key == *stable_key
        && item.revision_ref == *expected_revision_ref
}

fn related_locator_matches(state: &AppState, locator: &HumanReadLocator) -> bool {
    let HumanReadLocator::Related {
        relation,
        source_stable_key,
        expected_source_revision_ref,
        expected_frontier,
    } = locator
    else {
        return false;
    };
    state.related_context.as_ref().is_some_and(|context| {
        context.relation == *relation
            && context.source_stable_key == *source_stable_key
            && context.expected_source_revision_ref == *expected_source_revision_ref
            && context.expected_frontier == *expected_frontier
    })
}

fn related_context(state: &AppState) -> Option<crate::state::RelatedContext> {
    let detail = state.detail.as_ref()?;
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } =
        state.human.as_ref()?
    else {
        return None;
    };
    let relation = if detail.proposal_review.is_some() {
        evertrace_protocol::dto::HumanRelationKind::ProposalEvidence
    } else if detail.support_detail.is_some() {
        evertrace_protocol::dto::HumanRelationKind::SupportDependencies
    } else {
        return None;
    };
    Some(crate::state::RelatedContext {
        relation,
        source_stable_key: detail.stable_key.clone(),
        expected_source_revision_ref: detail.revision_ref.clone()?,
        expected_frontier: *frontier,
    })
}

fn snapshot_item_count(state: &AppState) -> usize {
    match state.human.as_ref() {
        Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { items, .. }) => {
            items.len()
        }
        _ => 0,
    }
}

fn human_request(
    state: &AppState,
    command: UiCommand,
) -> Option<evertrace_protocol::dto::HumanGovernanceRequest> {
    use evertrace_protocol::dto::{HumanGovernanceRequest, HumanReadRequest};
    let surface = human_surface(state.route);
    match command {
        UiCommand::OpenRelated => {
            let context = state.related_context.as_ref()?;
            Some(HumanGovernanceRequest::Read {
                request: HumanReadRequest::Related {
                    relation: context.relation,
                    source_stable_key: context.source_stable_key.clone(),
                    expected_source_revision_ref: context.expected_source_revision_ref.clone(),
                    expected_frontier: context.expected_frontier,
                    after: None,
                    limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                },
            })
        }
        UiCommand::NextPage => {
            let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                frontier,
                next_cursor: Some(after),
                ..
            } = state.human.as_ref()?
            else {
                return None;
            };
            let request = state.related_context.as_ref().map_or_else(
                || HumanReadRequest::List {
                    surface,
                    expected_frontier: Some(*frontier),
                    after: Some(after.clone()),
                    limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                },
                |context| HumanReadRequest::Related {
                    relation: context.relation,
                    source_stable_key: context.source_stable_key.clone(),
                    expected_source_revision_ref: context.expected_source_revision_ref.clone(),
                    expected_frontier: context.expected_frontier,
                    after: Some(after.clone()),
                    limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                },
            );
            Some(HumanGovernanceRequest::Read { request })
        }
        UiCommand::FirstPage => {
            let request = state.related_context.as_ref().map_or_else(
                || HumanReadRequest::List {
                    surface,
                    expected_frontier: None,
                    after: None,
                    limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                },
                |context| HumanReadRequest::Related {
                    relation: context.relation,
                    source_stable_key: context.source_stable_key.clone(),
                    expected_source_revision_ref: context.expected_source_revision_ref.clone(),
                    expected_frontier: context.expected_frontier,
                    after: None,
                    limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                },
            );
            Some(HumanGovernanceRequest::Read { request })
        }
        UiCommand::Detail => {
            let item = selected_item(state)?;
            let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } =
                state.human.as_ref()?
            else {
                return None;
            };
            Some(HumanGovernanceRequest::Read {
                request: HumanReadRequest::Detail {
                    surface,
                    object_ref: item.stable_key.clone(),
                    expected_frontier: *frontier,
                    expected_revision_ref: item.revision_ref.clone(),
                },
            })
        }
        _ => None,
    }
}

fn proposal_action(
    state: &AppState,
    decision: evertrace_protocol::dto::ProposalHumanDecision,
) -> Option<(
    u64,
    evertrace_protocol::dto::HumanActionRequest,
    Option<evertrace_protocol::dto::HumanProposalReview>,
)> {
    use evertrace_protocol::dto::{HumanActionRequest, HumanGovernanceResponse, HumanItemKind};
    let HumanGovernanceResponse::Snapshot { frontier, .. } = state.human.as_ref()? else {
        return None;
    };
    let item = selected_item(state)?;
    if item.item_kind != HumanItemKind::RevisionProposal {
        return None;
    }
    let proposal = item.proposal.as_ref()?;
    let review = match decision {
        evertrace_protocol::dto::ProposalHumanDecision::Accept => {
            let review = current_proposal_review(state)?;
            if !review.plain_accept_eligible {
                return None;
            }
            Some(review.clone())
        }
        evertrace_protocol::dto::ProposalHumanDecision::MergeAndAccept => {
            let review = current_proposal_review(state)?;
            if !review.merge_and_accept_eligible {
                return None;
            }
            Some(review.clone())
        }
        evertrace_protocol::dto::ProposalHumanDecision::EditAndAccept => return None,
        evertrace_protocol::dto::ProposalHumanDecision::Defer
        | evertrace_protocol::dto::ProposalHumanDecision::Reject => None,
    };
    Some((
        *frontier,
        HumanActionRequest::Proposal {
            proposal_id: proposal.proposal_id,
            expected_revision_id: proposal.current_revision_id,
            expected_fingerprint: proposal.fingerprint.clone(),
            decision,
            edited_payload: None,
        },
        review,
    ))
}

fn current_proposal_review(
    state: &AppState,
) -> Option<&evertrace_protocol::dto::HumanProposalReview> {
    current_detail(state)?.proposal_review.as_ref()
}

fn current_detail(state: &AppState) -> Option<&evertrace_protocol::dto::HumanSnapshotItem> {
    let selected = selected_item(state)?;
    let detail = state.detail.as_ref()?;
    if detail.stable_key != selected.stable_key
        || detail.object_ref != selected.object_ref
        || detail.revision_ref != selected.revision_ref
    {
        return None;
    }
    Some(detail)
}

fn future_operation_shell(state: &AppState) -> Option<crate::state::FutureOperationShell> {
    use crate::state::FutureOperationShell;
    if state.route == crate::Route::System {
        return Some(FutureOperationShell::Maintenance);
    }
    if state.route != crate::Route::Explorer {
        return None;
    }
    let detail = current_detail(state)?;
    let object_ref = detail.object_ref.clone()?;
    match (
        detail.object_kind.as_str(),
        detail.family,
        detail.lifecycle.as_deref(),
        detail.publication_state.as_deref(),
    ) {
        ("atom_revision", evertrace_protocol::dto::HumanObjectFamily::Atom, Some("active"), _) => {
            Some(FutureOperationShell::ForgetAtom(object_ref))
        }
        (
            "procedure_revision",
            evertrace_protocol::dto::HumanObjectFamily::Procedure,
            Some("active"),
            Some("active_probationary" | "active_stable"),
        ) => Some(FutureOperationShell::ForgetProcedure(object_ref)),
        (
            "core_membership",
            evertrace_protocol::dto::HumanObjectFamily::Atom,
            Some("active"),
            _,
        ) => Some(FutureOperationShell::ForgetCoreMembership(object_ref)),
        _ => None,
    }
}

fn proposal_action_unavailable_reason(
    state: &AppState,
    decision: evertrace_protocol::dto::ProposalHumanDecision,
) -> &'static str {
    let Some(item) = selected_item(state) else {
        return "select_current_proposal";
    };
    let Some(_) = item.proposal.as_ref() else {
        return "select_current_proposal";
    };
    let Some(review) = current_proposal_review(state) else {
        return "proposal_detail_required";
    };
    match decision {
        evertrace_protocol::dto::ProposalHumanDecision::Accept if !review.plain_accept_eligible => {
            "atomic_plain_acceptance_unavailable"
        }
        evertrace_protocol::dto::ProposalHumanDecision::MergeAndAccept
            if !review.merge_and_accept_eligible =>
        {
            "atomic_merge_and_accept_unavailable"
        }
        _ => "proposal_action_unavailable",
    }
}

fn negative_review_action(
    state: &AppState,
    decision: evertrace_protocol::dto::NegativeReviewDecision,
) -> Option<(
    u64,
    evertrace_protocol::dto::HumanActionRequest,
    Option<evertrace_protocol::dto::HumanProposalReview>,
)> {
    use evertrace_protocol::dto::{HumanActionRequest, HumanGovernanceResponse};
    let HumanGovernanceResponse::Snapshot { frontier, .. } = state.human.as_ref()? else {
        return None;
    };
    let review = selected_item(state)?.negative_review.as_ref()?;
    if !review.available_decisions.contains(&decision) {
        return None;
    }
    Some((
        *frontier,
        HumanActionRequest::NegativeReview {
            negative_evidence_id: review.negative_evidence_id,
            expected_review_revision_id: review.current_review_revision_id,
            decision,
        },
        None,
    ))
}

fn competing_selected_action(
    state: &AppState,
) -> Option<(
    u64,
    evertrace_protocol::dto::HumanActionRequest,
    Option<evertrace_protocol::dto::HumanProposalReview>,
)> {
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } =
        state.human.as_ref()?
    else {
        return None;
    };
    let detail = current_detail(state)?.competing_detail.as_ref()?;
    let chosen_attempt_id = *detail
        .eligible_attempt_ids
        .get(state.competing_candidate_selection)?;
    Some((
        *frontier,
        evertrace_protocol::dto::HumanActionRequest::ResolveCompetingSelected {
            expected_group_revision_id: detail.expected_group_revision_id,
            chosen_attempt_id,
        },
        None,
    ))
}

fn mark_new_attempt_action(
    state: &AppState,
) -> Option<(
    u64,
    evertrace_protocol::dto::HumanActionRequest,
    Option<evertrace_protocol::dto::HumanProposalReview>,
)> {
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } =
        state.human.as_ref()?
    else {
        return None;
    };
    let detail = current_detail(state)?;
    if detail.category != evertrace_protocol::dto::HumanItemCategory::AttemptResume
        || detail.object_kind != "attempt"
    {
        return None;
    }
    let expected_attempt_revision_id = detail.revision_ref.as_deref()?.parse().ok()?;
    Some((
        *frontier,
        evertrace_protocol::dto::HumanActionRequest::MarkNewAttempt {
            expected_attempt_revision_id,
        },
        None,
    ))
}

fn human_action_label(action: &evertrace_protocol::dto::HumanActionRequest) -> &'static str {
    use evertrace_protocol::dto::{HumanActionRequest, NegativeReviewDecision};
    match action {
        HumanActionRequest::NegativeReview {
            decision: NegativeReviewDecision::ResolveAsIneffective,
            ..
        } => "resolve as ineffective",
        HumanActionRequest::NegativeReview {
            decision: NegativeReviewDecision::DismissAttribution,
            ..
        } => "dismiss attribution",
        HumanActionRequest::NegativeReview {
            decision: NegativeReviewDecision::ConfirmHarm,
            ..
        } => "confirm harm",
        HumanActionRequest::NegativeReview {
            decision: NegativeReviewDecision::RequestRevision,
            ..
        } => "request revision",
        HumanActionRequest::Proposal { decision, .. } => match decision {
            evertrace_protocol::dto::ProposalHumanDecision::Accept => "accept proposal",
            evertrace_protocol::dto::ProposalHumanDecision::MergeAndAccept => "merge and accept",
            evertrace_protocol::dto::ProposalHumanDecision::Defer => "defer proposal",
            evertrace_protocol::dto::ProposalHumanDecision::Reject => "reject proposal",
            evertrace_protocol::dto::ProposalHumanDecision::EditAndAccept => {
                "edit and accept proposal"
            }
        },
        HumanActionRequest::SupportReplacement { .. } => "submit support replacement",
        HumanActionRequest::SupportDeprecate { .. } => "submit support deprecate",
        HumanActionRequest::ResolveCompetingSelected { .. } => "select competing attempt",
        HumanActionRequest::MarkNewAttempt { .. } => "mark new attempt",
        HumanActionRequest::Unavailable { .. } => "unavailable action",
    }
}

fn local_transport_error() -> evertrace_protocol::dto::HumanActionResult {
    local_unavailable("local_transport_busy")
}

fn local_unavailable(reason: &str) -> evertrace_protocol::dto::HumanActionResult {
    evertrace_protocol::dto::HumanActionResult {
        status: evertrace_protocol::dto::HumanActionStatus::Unavailable,
        current_revision_ref: None,
        audit_event_ref: None,
        reason: Some(reason.into()),
    }
}

fn selected_recovery_bundle(state: &AppState) -> Option<evertrace_domain::ids::RecoveryBundleId> {
    use std::str::FromStr;

    let item = selected_item(state)?;
    (state.route == crate::Route::Explorer && item.object_kind == "recovery_bundle")
        .then_some(item.object_ref.as_deref())
        .flatten()
        .and_then(|value| evertrace_domain::ids::RecoveryBundleId::from_str(value).ok())
}

fn recovery_request(
    state: &AppState,
) -> Option<evertrace_protocol::command::RequestRecoveryCommand> {
    use std::str::FromStr;

    let selection = state.recovery_selection?;
    let item = selected_item(state)?;
    if state.route != crate::Route::Explorer || item.object_kind != "worktree" {
        return None;
    }
    Some(evertrace_protocol::command::RequestRecoveryCommand {
        recovery_bundle_id: selection.recovery_bundle_id,
        target_worktree_instance_id: evertrace_domain::ids::WorktreeId::from_str(
            item.object_ref.as_deref()?,
        )
        .ok()?,
        application_kind: selection.application_kind,
    })
}

fn spawn_input(events: AppEventSender, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        while !stop.load(Ordering::Acquire) {
            match event::poll(Duration::from_millis(50)) {
                Ok(true) => match event::read() {
                    Ok(Event::Key(key)) => {
                        if events.blocking_send(AppEvent::Key(key)).is_err() {
                            break;
                        }
                    }
                    Ok(Event::Resize(width, height)) => {
                        if events
                            .blocking_send(AppEvent::Resize(width, height))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let _ = events.blocking_send(AppEvent::Shutdown);
                        break;
                    }
                },
                Ok(false) => {}
                Err(_) => {
                    let _ = events.blocking_send(AppEvent::Shutdown);
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::ids::{
        AtomId, AttemptId, CaptureReceiptId, CompetingAttemptGroupId, ExecutionLaneId, JobId,
        RecoveryBundleId, RevisionProposalId, WorktreeId,
    };
    use evertrace_domain::semantic::{
        ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload, AtomProvenance, AtomScope,
        AtomValue, EpistemicStatus, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalStatus, ProposalTargetId, ProposalTargetKind, RevisionProposal,
        SemanticQualifier, ValidityInterval,
    };
    use evertrace_domain::{
        ids::{ProcedureNegativeEvidenceId, RepositoryId, WorktreeSnapshotId},
        procedure::ProcedureNegativeReviewStatus,
        repository::{
            GitRegistrationState, OrderingIntegrity, RecoveryCaptureStatus, WorktreeKind,
            WorktreeLifecycle,
        },
        work::{
            CoverageLevel, LaneStatus, LivenessState, OrderingIntegrity as WorkOrderingIntegrity,
            PairingIntegrity, PayloadIntegrity, ReasoningVisibility, SourceCoverage,
        },
    };
    use evertrace_protocol::dto::{
        HealthMode, HumanCompetingDetail, HumanDegradedReason, HumanExecutionIntegrityDetail,
        HumanGovernanceResponse, HumanItemCategory, HumanItemKind, HumanJobBudget, HumanJobDetail,
        HumanJobState, HumanNegativeReviewMetadata, HumanObjectFamily, HumanProposalMetadata,
        HumanProposalReview, HumanRecoveryDetail, HumanRelationKind, HumanRowClass,
        HumanSnapshotItem, HumanSnapshotStatus, HumanSystemDetail, HumanWorktreeDetail,
        NegativeReviewDecision, PROTOCOL_VERSION, ProposalHumanDecision,
    };
    use evertrace_protocol::response::HealthResponse;

    #[test]
    fn recovery_requires_explicit_bundle_target_and_one_confirmation() {
        let bundle_one = RecoveryBundleId::new_v7();
        let bundle_two = RecoveryBundleId::new_v7();
        let worktree_one = WorktreeId::new_v7();
        let worktree_two = WorktreeId::new_v7();
        let mut app = App::new();
        app.dispatch(UiCommand::Navigate(crate::Route::Explorer));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![
                    snapshot_item("worktree", worktree_two.to_string()),
                    snapshot_item("recovery_bundle", bundle_one.to_string()),
                    snapshot_item("recovery_bundle", bundle_two.to_string()),
                    snapshot_item("worktree", worktree_one.to_string()),
                ],
                next_cursor: None,
            },
        });
        app.dispatch(UiCommand::PrepareRecovery(
            evertrace_domain::repository::RecoveryApplicationKind::FileRestore,
        ));
        assert!(app.state.recovery_selection.is_none());
        assert_eq!(
            app.state
                .last_action
                .as_ref()
                .and_then(|result| result.reason.as_deref()),
            Some("select_recovery_bundle_first")
        );

        app.state.selection = 2;
        app.dispatch(UiCommand::PrepareRecovery(
            evertrace_domain::repository::RecoveryApplicationKind::FileRestore,
        ));
        let draft = render_app(&app, 100, 30);
        assert!(draft.contains(&bundle_two.to_string()));
        assert!(draft.contains("select target Worktree"));
        app.state.selection = 3;
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::None);
        let request = app.state.recovery_confirmation.as_ref().unwrap();
        assert_eq!(request.recovery_bundle_id, bundle_two);
        assert_eq!(request.target_worktree_instance_id, worktree_one);
        assert_eq!(
            request.application_kind,
            evertrace_domain::repository::RecoveryApplicationKind::FileRestore
        );
        let confirmation = render_app(&app, 100, 30);
        assert!(confirmation.contains(&bundle_two.to_string()));
        assert!(confirmation.contains(&worktree_one.to_string()));
        assert!(confirmation.contains("FileRestore"));
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::ConfirmRecovery);
        let request = app.take_recovery_confirmation().unwrap();
        assert_eq!(request.recovery_bundle_id, bundle_two);
        assert!(app.take_recovery_confirmation().is_none());

        let source_snapshot_id = WorktreeSnapshotId::new_v7();
        let mut bundle_detail = snapshot_item("recovery_bundle", bundle_two.to_string());
        bundle_detail.recovery_detail = Some(HumanRecoveryDetail::Bundle {
            bundle_id: bundle_two,
            source_worktree_id: worktree_two,
            source_snapshot_id,
            capture_status: RecoveryCaptureStatus::Complete,
            ordering_integrity: OrderingIntegrity::Complete,
            captured_bytes: 12,
            tracked_diff_count: 1,
            tracked_file_count: 0,
            index_state_count: 0,
            untracked_file_count: 0,
            untracked_artifact_count: 0,
            metadata_artifact_count: 0,
            config_run_count: 0,
            attempt_anchor_count: 0,
            omission_counts: Vec::new(),
        });
        app.state.detail = Some(bundle_detail.clone());
        let rendered = render_app(&app, 100, 30);
        assert!(rendered.contains(&bundle_two.to_string()));
        assert!(rendered.contains("source worktree/snapshot"));
        assert!(rendered.contains("captured bytes: 12"));

        let mut worktree_detail = snapshot_item("worktree", worktree_one.to_string());
        worktree_detail.worktree_detail = Some(HumanWorktreeDetail {
            worktree_id: worktree_one,
            repository_id: RepositoryId::new_v7(),
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            registration_state: GitRegistrationState::Registered,
            current_snapshot_id: Some(source_snapshot_id),
        });
        app.state.detail = Some(worktree_detail.clone());
        assert!(render_app(&app, 100, 30).contains("Registered"));
        worktree_detail.recovery_detail = bundle_detail.recovery_detail;
        assert!(
            !HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![worktree_detail],
                next_cursor: None,
            }
            .validate()
        );

        let lane_id = ExecutionLaneId::new_v7();
        let mut lane_detail = snapshot_item("execution_lane", lane_id.to_string());
        lane_detail.revision_ref = Some(format!("{lane_id}@1"));
        assert!(
            HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![lane_detail.clone()],
                next_cursor: None,
            }
            .validate()
        );
        lane_detail.execution_integrity_detail = Some(HumanExecutionIntegrityDetail::Lane {
            execution_lane_id: lane_id,
            lane_revision: 1,
            parent_lane_id: None,
            status: LaneStatus::Active,
            terminal_kind: None,
            liveness_state: LivenessState::Live,
            finalized: false,
            event_watermark: 3,
            active_capture_receipt_revision_id: CaptureReceiptId::new_v7(),
            coverage_level: CoverageLevel::Full,
            source_coverage: SourceCoverage::Open,
            pairing_integrity: PairingIntegrity::Complete,
            payload_integrity: PayloadIntegrity::Complete,
            ordering_integrity: WorkOrderingIntegrity::Complete,
            reasoning_visibility: vec![ReasoningVisibility::Raw],
        });
        app.state.detail = Some(lane_detail.clone());
        let rendered = render_app(&app, 100, 30);
        assert!(rendered.contains("lane/revision"));
        assert!(rendered.contains(&lane_id.to_string()));
        let valid_lane_detail = lane_detail.clone();
        lane_detail.object_kind = "capture_receipt".into();
        assert!(
            !HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![lane_detail],
                next_cursor: None,
            }
            .validate()
        );
        let mut wrong_family = valid_lane_detail;
        wrong_family.family = HumanObjectFamily::Evidence;
        wrong_family.category = HumanItemCategory::Evidence;
        assert!(
            !HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![wrong_family],
                next_cursor: None,
            }
            .validate()
        );

        let job_id = JobId::new_v7();
        let mut job_detail = snapshot_item("runtime_event", "ignored".into());
        job_detail.stable_key = format!("runtime:job:{job_id}");
        job_detail.row_class = HumanRowClass::Runtime;
        job_detail.family = HumanObjectFamily::Runtime;
        job_detail.category = HumanItemCategory::Runtime;
        job_detail.object_ref = None;
        job_detail.system_detail = Some(HumanSystemDetail::Job {
            detail: Box::new(HumanJobDetail {
                job_id,
                target_revision: "object:target".into(),
                target_watermark: 3,
                target_generation: 1,
                job_kind: "objects_projection".into(),
                algorithm_revision: "s31-test-v1".into(),
                model_id: None,
                priority: 1,
                state: HumanJobState::Queued,
                attempt: 1,
                backoff_until_us: None,
                lease_until_us: None,
                config_hash: [7; 32],
                budget: HumanJobBudget {
                    max_items: 1,
                    max_bytes: None,
                    max_input_tokens: None,
                    max_output_tokens: None,
                    max_calls: None,
                    max_wall_time_ms: 10,
                },
                terminal_reason: None,
                terminal_result_ref: None,
            }),
        });
        app.state.detail = Some(job_detail.clone());
        let rendered = render_app(&app, 100, 30);
        assert!(rendered.contains(&job_id.to_string()));
        assert!(rendered.contains("objects_projection"));
        let mut forged = job_detail.clone();
        forged.stable_key = "runtime:job:forged".into();
        assert!(
            !HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![forged],
                next_cursor: None,
            }
            .validate()
        );
        job_detail.object_kind = "session_import_current".into();
        assert!(
            !HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![job_detail],
                next_cursor: None,
            }
            .validate()
        );

        app.state.selection = 1;
        app.dispatch(UiCommand::PrepareRecovery(
            evertrace_domain::repository::RecoveryApplicationKind::Patch,
        ));
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.recovery_selection.is_none());
        assert!(app.state.recovery_confirmation.is_none());
    }

    #[test]
    fn proposal_action_and_read_requests_use_current_typed_snapshot() {
        let proposal_id = "proposal:01900000-0000-7000-8000-000000000031"
            .parse::<RevisionProposalId>()
            .unwrap();
        let revision_id = "01900000-0000-7000-8000-000000000032"
            .parse::<evertrace_domain::revision::RevisionId>()
            .unwrap();
        let repository_id = "repo:01900000-0000-7000-8000-000000000033"
            .parse::<RepositoryId>()
            .unwrap();
        let mut reviewed = RevisionProposal {
            proposal_id,
            proposal_revision_id: revision_id,
            parent_proposal_revision_id: None,
            target_kind: ProposalTargetKind::Atom,
            target_id: None,
            base_revision_id: None,
            operation: ProposalOperation::Create,
            payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                draft: AtomDraft {
                    kind: AtomKind::Constraint,
                    epistemic_status: EpistemicStatus::NotApplicable,
                    value: AtomValue {
                        text: "keep the reviewed invariant".into(),
                        subject: "governance".into(),
                        predicate: "preserves".into(),
                        object: Some("evidence".into()),
                        qualifiers: vec![SemanticQualifier {
                            name: "scope".into(),
                            value: "repository".into(),
                        }],
                        critical_revision_refs: Vec::new(),
                    },
                    scope: AtomScope::Repository {
                        repository_instance_id: repository_id,
                    },
                    applicability_expr: ApplicabilityExpr::Always,
                    future_cue_lifecycle_exprs: None,
                    validity_interval: ValidityInterval {
                        valid_from_us: 1,
                        valid_until_us: None,
                    },
                    provenance: vec![AtomProvenance::AgentClaimed],
                    source_observation_refs: Vec::new(),
                    evidence_refs: vec!["source:one".into()],
                    supersedes_revision_refs: Vec::new(),
                    supports_revision_refs: Vec::new(),
                    contradicts_revision_refs: Vec::new(),
                },
            })),
            evidence_refs: vec!["source:one".into()],
            source_cohort_refs: vec!["source:one".into()],
            source_cohort_hash: [0; 32],
            fingerprint: [0; 32],
            eligibility: ProposalEligibility::ManualRequired,
            status: ProposalStatus::Pending,
            waiting_on: Vec::new(),
            review_reason: None,
            created_by: ProposalCreatedBy::Agent,
            acceptance: None,
            created_at_us: 1,
            reviewed_at_us: None,
        };
        reviewed.source_cohort_hash = reviewed.recompute_source_cohort_hash().unwrap();
        reviewed.fingerprint = reviewed.recompute_fingerprint().unwrap();
        assert!(reviewed.validate().is_ok());
        let item = HumanSnapshotItem {
            item_kind: HumanItemKind::RevisionProposal,
            proposal: Some(HumanProposalMetadata {
                proposal_id,
                current_revision_id: revision_id,
                fingerprint: evertrace_domain::evidence::hex(&reviewed.fingerprint),
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                operation: ProposalOperation::Create,
                base_revision_id: None,
                source_cohort_refs: vec!["source:one".into()],
                eligibility: ProposalEligibility::ManualRequired,
                status: ProposalStatus::Pending,
            }),
            proposal_review: None,
            support_detail: None,
            competing_detail: None,
            negative_review: None,
            recovery_detail: None,
            worktree_detail: None,
            execution_integrity_detail: None,
            system_detail: None,
            stable_key: "proposal-row".into(),
            row_class: HumanRowClass::Object,
            family: HumanObjectFamily::RevisionProposal,
            category: HumanItemCategory::Proposal,
            object_kind: "revision_proposal_revision".into(),
            object_ref: Some(proposal_id.to_string()),
            revision_ref: Some(revision_id.to_string()),
            lifecycle: Some("pending".into()),
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            scope_ref: None,
            source_event_seq: 9,
        };
        let mut app = App::new();
        app.handle(AppEvent::Health(HealthResponse {
            protocol_version: PROTOCOL_VERSION,
            mode: HealthMode::Normal,
            config_version: 1,
            effective_config_hash: "0".repeat(64),
            algorithm_revision: 1,
        }));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                frontier: 9,
                status: HumanSnapshotStatus::Degraded,
                degraded_reasons: vec![HumanDegradedReason::CurrentJobFailed],
                items: vec![item.clone()],
                next_cursor: Some("proposal-row".into()),
            },
        });
        assert!(matches!(
            human_request(&app.state, UiCommand::NextPage),
            Some(evertrace_protocol::dto::HumanGovernanceRequest::Read { .. })
        ));
        assert!(matches!(
            human_request(&app.state, UiCommand::Detail),
            Some(evertrace_protocol::dto::HumanGovernanceRequest::Read { .. })
        ));
        app.dispatch(UiCommand::PrepareProposal(ProposalHumanDecision::Defer));
        let (frontier, action, review) = app.state.proposal_confirmation.take().unwrap();
        assert_eq!(frontier, 9);
        assert!(review.is_none());
        assert!(matches!(
            action,
            evertrace_protocol::dto::HumanActionRequest::Proposal {
                proposal_id: current,
                expected_revision_id: current_revision,
                decision: ProposalHumanDecision::Defer,
                ..
            } if current == proposal_id && current_revision == revision_id
        ));
        app.dispatch(UiCommand::PrepareProposal(ProposalHumanDecision::Reject));
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.proposal_confirmation.is_none());
        app.dispatch(UiCommand::PrepareProposal(ProposalHumanDecision::Accept));
        assert!(app.state.proposal_confirmation.is_none());
        assert_eq!(
            app.state
                .last_action
                .as_ref()
                .and_then(|result| result.reason.as_deref()),
            Some("proposal_detail_required")
        );
        let mut detail_item = item.clone();
        detail_item.proposal_review = Some(HumanProposalReview {
            proposal: Box::new(reviewed.clone()),
            plain_accept_eligible: true,
            merge_and_accept_eligible: false,
        });
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::Detail {
                expected_frontier: 9,
                stable_key: "proposal-row".into(),
                expected_revision_ref: Some(revision_id.to_string()),
            },
            response: HumanGovernanceResponse::Snapshot {
                frontier: 9,
                status: HumanSnapshotStatus::Degraded,
                degraded_reasons: vec![HumanDegradedReason::CurrentJobFailed],
                items: vec![detail_item],
                next_cursor: None,
            },
        });
        let compact = render_app(&app, 60, 20);
        assert!(compact.contains("Esc back"));
        app.state.detail_scroll = 12;
        let wide = render_app(&app, 100, 30);
        assert!(wide.contains("keep the reviewed invariant"));
        app.state.detail_scroll = 24;
        assert!(render_app(&app, 100, 30).contains("Repository"));
        assert_eq!(
            wide,
            include_str!("../../../fixtures/tui/s31/wide.txt").trim_end()
        );
        assert_eq!(
            compact,
            include_str!("../../../fixtures/tui/s31/compact.txt").trim_end()
        );
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Char('E'),
                KeyModifiers::SHIFT,
            ))),
            UiCommand::OpenProposalEditor
        );
        assert!(app.state.proposal_edit.is_some());
        let editor = render_app(&app, 60, 20);
        assert!(editor.contains("EDIT PROPOSAL DOCUMENT"));
        assert!(editor.contains("Ctrl+S submit"));
        assert!(editor.contains("Esc cancel"));
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Char('q'),
                KeyModifiers::NONE,
            ))),
            UiCommand::None
        );
        assert!(!app.state.quit);
        assert!(
            app.state
                .proposal_edit
                .as_ref()
                .unwrap()
                .document
                .ends_with('q')
        );
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Backspace,
            KeyModifiers::NONE,
        )));
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        )));
        assert!(app.state.proposal_edit.is_none());
        assert!(app.state.proposal_confirmation.is_none());

        app.dispatch(UiCommand::OpenProposalEditor);
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Char('s'),
                KeyModifiers::CONTROL,
            ))),
            UiCommand::None
        );
        assert_eq!(
            app.state
                .proposal_edit
                .as_ref()
                .and_then(|edit| edit.error.as_deref()),
            Some("edited_payload_is_unchanged")
        );
        assert!(app.state.proposal_confirmation.is_none());
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
        )));
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL,
        )));
        assert!(
            app.state
                .proposal_edit
                .as_ref()
                .and_then(|edit| edit.error.as_deref())
                .is_some_and(|error| error.starts_with("parse_error:"))
        );
        assert!(app.state.proposal_confirmation.is_none());
        let edit = app.state.proposal_edit.as_mut().unwrap();
        edit.document = edit
            .document
            .trim_end_matches('x')
            .replace("keep the reviewed invariant", "keep the edited invariant");
        edit.cursor = edit.document.len();
        edit.error = None;
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL,
        )));
        assert!(matches!(
            app.state.proposal_confirmation.as_ref(),
            Some((9, evertrace_protocol::dto::HumanActionRequest::Proposal {
                proposal_id: current,
                expected_revision_id: current_revision,
                decision: ProposalHumanDecision::EditAndAccept,
                edited_payload: Some(payload),
                ..
            }, Some(frozen)))
                if *current == proposal_id
                    && *current_revision == revision_id
                    && payload.as_ref() != &reviewed.payload
                    && frozen.proposal.as_ref() == &reviewed
        ));
        assert!(app.state.proposal_edit.is_none());
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.proposal_confirmation.is_none());
        let proposal_human = app.state.human.clone();
        let proposal_detail = app.state.detail.clone();
        let ProposalPayload::Atom(initial) = &reviewed.payload else {
            unreachable!()
        };
        let AtomProposalPayload::Create { draft } = initial.as_ref() else {
            unreachable!()
        };
        let initial_replacement = ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
            draft: draft.clone(),
        }));
        let validation_revision_id = evertrace_domain::revision::RevisionId::new_v7();
        let support_contract_revision_id = evertrace_domain::revision::RevisionId::new_v7();
        let support_revision_id = evertrace_domain::revision::RevisionId::new_v7();
        let mut support_item = item.clone();
        support_item.item_kind = HumanItemKind::Generic;
        support_item.proposal = None;
        support_item.proposal_review = None;
        support_item.stable_key = "support-row".into();
        support_item.family = HumanObjectFamily::Atom;
        support_item.category = HumanItemCategory::Support;
        support_item.object_kind = "global_support_validation".into();
        support_item.object_ref = Some(support_contract_revision_id.to_string());
        support_item.revision_ref = Some(validation_revision_id.to_string());
        support_item.lifecycle = Some("insufficient".into());
        support_item.authority = None;
        support_item.support_detail = Some(evertrace_protocol::dto::HumanSupportDetail {
            support_contract_revision_id,
            successor_ref: evertrace_domain::revision::RevisionId::new_v7().to_string(),
            validation_revision_id,
            state: evertrace_domain::semantic::GlobalSupportState::Insufficient,
            dependency_generation: 2,
            provenance_degraded: true,
            threshold: evertrace_domain::semantic::SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: true,
            },
            support_revision_refs: vec![support_revision_id],
            authorization_revision_refs: vec![evertrace_domain::revision::RevisionId::new_v7()],
            surviving_support_refs: Vec::new(),
            invalid_or_missing_refs: vec![support_revision_id],
            trigger_refs: vec!["support:trigger".into()],
            initial_replacement_payload: Some(Box::new(initial_replacement)),
            deprecate_available: true,
        });
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            frontier: 11,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![support_item.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(support_item.clone());
        app.state.selection = 0;
        app.dispatch(UiCommand::OpenProposalEditor);
        let support_editor = render_app(&app, 60, 20);
        assert!(support_editor.contains("EDIT SUPPORT REPLACEMENT"));
        assert!(support_editor.contains("Ctrl+S submit"));
        let edit = app.state.proposal_edit.as_mut().unwrap();
        edit.document = edit.document.replace(
            "keep the reviewed invariant",
            "keep the support replacement",
        );
        edit.cursor = edit.document.len();
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL,
        )));
        assert!(matches!(
            app.state.proposal_confirmation.as_ref(),
            Some((11, evertrace_protocol::dto::HumanActionRequest::SupportReplacement {
                expected_validation_revision_id: current,
                edited_payload,
            }, None)) if *current == validation_revision_id
                && edited_payload.as_ref() != support_item
                    .support_detail
                    .as_ref()
                    .unwrap()
                    .initial_replacement_payload
                    .as_ref()
                    .unwrap()
                    .as_ref()
        ));
        app.dispatch(UiCommand::CancelModal);
        app.dispatch(UiCommand::OpenSupportDeprecateEditor);
        let deprecate_editor = render_app(&app, 60, 20);
        assert!(deprecate_editor.contains("SUBMIT SUPPORT DEPRECATION"));
        let edit = app.state.proposal_edit.as_mut().unwrap();
        edit.document = edit
            .document
            .replace("\"reason\": \"\"", "\"reason\": \"support withdrawn\"");
        edit.cursor = edit.document.len();
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL,
        )));
        assert!(matches!(
            app.state.proposal_confirmation.as_ref(),
            Some((11, evertrace_protocol::dto::HumanActionRequest::SupportDeprecate {
                expected_validation_revision_id: current,
                reason,
            }, None)) if *current == validation_revision_id && reason == "support withdrawn"
        ));
        app.dispatch(UiCommand::CancelModal);
        support_item
            .support_detail
            .as_mut()
            .unwrap()
            .initial_replacement_payload = None;
        support_item
            .support_detail
            .as_mut()
            .unwrap()
            .deprecate_available = false;
        app.state.detail = Some(support_item);
        app.dispatch(UiCommand::OpenProposalEditor);
        assert!(app.state.proposal_edit.is_none());
        assert!(app.state.proposal_confirmation.is_none());
        assert_eq!(
            app.state
                .last_action
                .as_ref()
                .and_then(|result| result.reason.as_deref()),
            Some("support_replacement_unavailable")
        );
        app.dispatch(UiCommand::OpenSupportDeprecateEditor);
        assert!(app.state.proposal_edit.is_none());
        assert_eq!(
            app.state
                .last_action
                .as_ref()
                .and_then(|result| result.reason.as_deref()),
            Some("support_deprecate_unavailable")
        );
        app.state.human = proposal_human;
        app.state.detail = proposal_detail;
        app.state.detail_scroll = 0;
        app.dispatch(UiCommand::PrepareProposal(ProposalHumanDecision::Accept));
        assert!(matches!(
            app.state.proposal_confirmation.as_ref(),
            Some((9, evertrace_protocol::dto::HumanActionRequest::Proposal {
                proposal_id: current,
                expected_revision_id: current_revision,
                decision: ProposalHumanDecision::Accept,
                ..
            }, Some(frozen))) if *current == proposal_id && *current_revision == revision_id && frozen.proposal.as_ref() == &reviewed
        ));
        let base = evertrace_domain::revision::RevisionId::new_v7();
        let other = evertrace_domain::revision::RevisionId::new_v7();
        let mut merge = reviewed.clone();
        merge.proposal_id = RevisionProposalId::new_v7();
        merge.proposal_revision_id = evertrace_domain::revision::RevisionId::new_v7();
        merge.target_id = Some(ProposalTargetId::Atom(AtomId::new_v7()));
        merge.base_revision_id = Some(base);
        merge.operation = ProposalOperation::Merge;
        let ProposalPayload::Atom(payload) = &reviewed.payload else {
            unreachable!()
        };
        let AtomProposalPayload::Create { mut draft } = payload.as_ref().clone() else {
            unreachable!()
        };
        draft.supersedes_revision_refs = vec![base, other];
        draft.supersedes_revision_refs.sort();
        merge.payload = ProposalPayload::Atom(Box::new(AtomProposalPayload::Merge {
            merged_revision_refs: draft.supersedes_revision_refs.clone(),
            draft,
        }));
        merge.source_cohort_hash = merge.recompute_source_cohort_hash().unwrap();
        merge.fingerprint = merge.recompute_fingerprint().unwrap();
        assert!(merge.validate().is_ok());
        let mut merge_item = item;
        merge_item.proposal = Some(HumanProposalMetadata {
            proposal_id: merge.proposal_id,
            current_revision_id: merge.proposal_revision_id,
            fingerprint: evertrace_domain::evidence::hex(&merge.fingerprint),
            target_kind: merge.target_kind,
            target_id: merge.target_id,
            operation: merge.operation,
            base_revision_id: merge.base_revision_id,
            source_cohort_refs: merge.source_cohort_refs.clone(),
            eligibility: merge.eligibility,
            status: merge.status,
        });
        merge_item.object_ref = Some(merge.proposal_id.to_string());
        merge_item.revision_ref = Some(merge.proposal_revision_id.to_string());
        merge_item.proposal_review = Some(HumanProposalReview {
            proposal: Box::new(merge.clone()),
            plain_accept_eligible: false,
            merge_and_accept_eligible: true,
        });
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            frontier: 10,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![merge_item.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(merge_item);
        app.state.proposal_confirmation = None;
        app.dispatch(UiCommand::PrepareProposal(ProposalHumanDecision::Accept));
        assert!(app.state.proposal_confirmation.is_none());
        assert_eq!(
            app.state
                .last_action
                .as_ref()
                .and_then(|result| result.reason.as_deref()),
            Some("atomic_plain_acceptance_unavailable")
        );
        app.handle(AppEvent::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('m'),
            crossterm::event::KeyModifiers::NONE,
        )));
        assert!(matches!(
            app.state.proposal_confirmation.as_ref(),
            Some((10, evertrace_protocol::dto::HumanActionRequest::Proposal {
                decision: ProposalHumanDecision::MergeAndAccept,
                ..
            }, Some(frozen))) if frozen.merge_and_accept_eligible
        ));
        app.state.proposal_confirmation = None;
        assert_eq!(app.dispatch(UiCommand::OpenRelated), UiCommand::OpenRelated);
        assert!(matches!(
            human_request(&app.state, UiCommand::OpenRelated),
            Some(evertrace_protocol::dto::HumanGovernanceRequest::Read {
                request: evertrace_protocol::dto::HumanReadRequest::Related {
                    relation: HumanRelationKind::ProposalEvidence,
                    source_stable_key,
                    expected_source_revision_ref,
                    expected_frontier: 10,
                    after: None,
                    ..
                }
            }) if source_stable_key == "proposal-row"
                && expected_source_revision_ref == merge.proposal_revision_id.to_string()
        ));
        let related = snapshot_item("source_receipt", "receipt:related".into());
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: HumanReadLocator::Related {
                relation: HumanRelationKind::ProposalEvidence,
                source_stable_key: "proposal-row".into(),
                expected_source_revision_ref: merge.proposal_revision_id.to_string(),
                expected_frontier: 10,
            },
            response: HumanGovernanceResponse::Snapshot {
                frontier: 10,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![related],
                next_cursor: None,
            },
        });
        assert_eq!(app.state.route, crate::Route::Explorer);
        assert!(matches!(
            human_request(&app.state, UiCommand::Detail),
            Some(evertrace_protocol::dto::HumanGovernanceRequest::Read {
                request: evertrace_protocol::dto::HumanReadRequest::Detail { .. }
            })
        ));
        app.dispatch(UiCommand::Navigate(crate::Route::Explorer));
        assert!(app.state.proposal_confirmation.is_none());
        assert!(app.state.detail.is_none());

        let atom_id = AtomId::new_v7();
        let mut atom = snapshot_item("atom_revision", atom_id.to_string());
        atom.family = HumanObjectFamily::Atom;
        atom.category = HumanItemCategory::Semantic;
        atom.lifecycle = Some("active".into());
        atom.revision_ref = Some(evertrace_domain::revision::RevisionId::new_v7().to_string());
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            frontier: 11,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![atom.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(atom);
        app.dispatch(UiCommand::OpenFutureOperationShell);
        assert!(matches!(
            app.state.future_operation_shell.as_ref(),
            Some(crate::state::FutureOperationShell::ForgetAtom(object_ref))
                if object_ref == &atom_id.to_string()
        ));
        assert!(human_request(&app.state, UiCommand::OpenFutureOperationShell).is_none());
        let forget = render_app(&app, 60, 20);
        assert!(forget.contains(&atom_id.to_string()));
        assert!(forget.contains("Object Forget is not source erasure"));
        assert!(forget.contains("No command will be sent"));
        assert_eq!(
            app.dispatch(UiCommand::PrepareProposal(ProposalHumanDecision::Defer)),
            UiCommand::None
        );
        assert!(app.state.proposal_confirmation.is_none());
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::None);
        assert!(app.state.future_operation_shell.is_some());
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.future_operation_shell.is_none());

        app.dispatch(UiCommand::Navigate(crate::Route::System));
        app.dispatch(UiCommand::OpenFutureOperationShell);
        assert!(human_request(&app.state, UiCommand::OpenFutureOperationShell).is_none());
        let maintenance = render_app(&app, 60, 20);
        assert!(maintenance.contains("Repository purge"));
        assert!(maintenance.contains("Backup/verify"));
        assert!(maintenance.contains("offline-only"));
        assert!(maintenance.contains("Orphan GC"));
        assert!(maintenance.contains("No command will be sent"));
        assert!(app.state.proposal_confirmation.is_none());
        assert!(app.state.recovery_confirmation.is_none());
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::None);
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.future_operation_shell.is_none());
    }

    #[test]
    fn stale_surface_read_is_ignored_without_refresh() {
        let mut app = App::new();
        let command = app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                frontier: 3,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: Vec::new(),
                next_cursor: None,
            },
        });
        assert_eq!(command, UiCommand::None);
        assert!(app.state.human.is_none());
    }

    #[test]
    fn competing_selection_only_uses_daemon_candidates_and_confirms_once() {
        let group_id = CompetingAttemptGroupId::new_v7();
        let revision_id = evertrace_domain::revision::RevisionId::new_v7();
        let mut candidates = vec![AttemptId::new_v7(), AttemptId::new_v7()];
        candidates.sort();
        let mut item = snapshot_item("competing_attempt_group", group_id.to_string());
        item.category = HumanItemCategory::CompetingResolution;
        item.revision_ref = Some(revision_id.to_string());
        item.competing_detail = Some(HumanCompetingDetail {
            expected_group_revision_id: revision_id,
            eligible_attempt_ids: candidates.clone(),
        });
        let snapshot = HumanGovernanceResponse::Snapshot {
            frontier: 7,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![item.clone()],
            next_cursor: None,
        };
        assert!(snapshot.validate());
        let mut app = App::new();
        app.state.human = Some(snapshot);
        app.state.detail = Some(item);

        assert_eq!(
            app.dispatch(UiCommand::SelectCompetingNext),
            UiCommand::None
        );
        assert!(human_request(&app.state, UiCommand::PrepareCompetingSelected).is_none());
        app.dispatch(UiCommand::PrepareCompetingSelected);
        let (frontier, action, review) = app.state.proposal_confirmation.clone().unwrap();
        assert_eq!(frontier, 7);
        assert!(review.is_none());
        assert_eq!(
            action,
            evertrace_protocol::dto::HumanActionRequest::ResolveCompetingSelected {
                expected_group_revision_id: revision_id,
                chosen_attempt_id: candidates[1],
            }
        );
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::ConfirmProposal);
    }

    #[test]
    fn negative_review_only_confirms_a_daemon_available_decision() {
        let negative_id = ProcedureNegativeEvidenceId::new_v7();
        let review_revision = evertrace_domain::revision::RevisionId::new_v7();
        let mut item = snapshot_item("procedure_negative_review", review_revision.to_string());
        item.category = HumanItemCategory::NegativeReview;
        item.revision_ref = Some(review_revision.to_string());
        item.negative_review = Some(HumanNegativeReviewMetadata {
            negative_evidence_id: negative_id,
            current_review_revision_id: review_revision,
            status: ProcedureNegativeReviewStatus::Pending,
            available_decisions: vec![NegativeReviewDecision::DismissAttribution],
        });
        let mut app = App::new();
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                frontier: 8,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![item],
                next_cursor: None,
            },
        });
        app.dispatch(UiCommand::PrepareNegativeReview(
            NegativeReviewDecision::DismissAttribution,
        ));
        assert!(matches!(
            app.state.proposal_confirmation,
            Some((8, evertrace_protocol::dto::HumanActionRequest::NegativeReview {
                negative_evidence_id,
                expected_review_revision_id,
                decision: NegativeReviewDecision::DismissAttribution,
            }, None)) if negative_evidence_id == negative_id && expected_review_revision_id == review_revision
        ));
        app.state.proposal_confirmation = None;
        app.dispatch(UiCommand::PrepareNegativeReview(
            NegativeReviewDecision::RequestRevision,
        ));
        assert!(app.state.proposal_confirmation.is_none());
        assert_eq!(
            app.state
                .last_action
                .as_ref()
                .and_then(|result| result.reason.as_deref()),
            Some("negative_review_proof_unavailable")
        );
    }

    #[test]
    fn stale_detail_for_previous_selection_is_ignored() {
        let first = snapshot_item("task", "task:first".into());
        let second = snapshot_item("task", "task:second".into());
        let first_locator = HumanReadLocator::Detail {
            expected_frontier: 4,
            stable_key: first.stable_key.clone(),
            expected_revision_ref: first.revision_ref.clone(),
        };
        let mut app = App::new();
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                frontier: 4,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![first.clone(), second],
                next_cursor: None,
            },
        });
        app.dispatch(UiCommand::SelectNext);
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: first_locator,
            response: HumanGovernanceResponse::Snapshot {
                frontier: 4,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![first],
                next_cursor: None,
            },
        });
        assert!(app.state.detail.is_none());
        assert_eq!(app.state.selection, 1);
    }

    #[test]
    fn disconnected_and_server_stopping_are_not_rendered_as_empty_pages() {
        let mut disconnected = App::new();
        disconnected.handle(AppEvent::Disconnected);
        assert!(render_app(&disconnected, 100, 30).contains("Daemon disconnected"));

        let mut stopping = App::new();
        stopping.handle(AppEvent::Notification(
            evertrace_protocol::notification::Notification::ServerStopping,
        ));
        assert!(render_app(&stopping, 100, 30).contains("Daemon stopping; read unavailable"));
    }

    fn snapshot_item(family: &str, object_ref: String) -> HumanSnapshotItem {
        let (category, object_family) = match family {
            "recovery_bundle" => (HumanItemCategory::RecoveryEvidence, HumanObjectFamily::Work),
            "worktree" => (HumanItemCategory::Repository, HumanObjectFamily::Work),
            _ => (HumanItemCategory::Work, HumanObjectFamily::Work),
        };
        HumanSnapshotItem {
            item_kind: HumanItemKind::Generic,
            proposal: None,
            proposal_review: None,
            support_detail: None,
            competing_detail: None,
            negative_review: None,
            recovery_detail: None,
            worktree_detail: None,
            execution_integrity_detail: None,
            system_detail: None,
            stable_key: format!("object:{family}:{object_ref}"),
            row_class: HumanRowClass::Object,
            family: object_family,
            category,
            object_kind: family.into(),
            object_ref: Some(object_ref),
            revision_ref: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            scope_ref: None,
            source_event_seq: 1,
        }
    }

    fn render_app(app: &App, width: u16, height: u16) -> String {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
