use crate::{
    AppEvent, AppEventSender, AppState, ConnectionState, Route, UiCommand,
    app_event::HumanReadLocator, client, components, keymap, layout, views,
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
    hit_regions: std::cell::RefCell<Vec<(Rect, UiCommand)>>,
    visible_layout: std::cell::RefCell<layout::ShellLayout>,
}
mod interaction;

const MAX_PROPOSAL_EDIT_DOCUMENT: usize = evertrace_protocol::dto::MAX_FRAME_SIZE / 2;

impl App {
    pub fn new() -> Self {
        Self::with_language(crate::Language::environment())
    }

    pub fn with_language(language: crate::Language) -> Self {
        let mut state = AppState {
            language,
            ..AppState::default()
        };
        state.ui.read_generation = 1;
        Self {
            state,
            hit_regions: std::cell::RefCell::new(Vec::new()),
            visible_layout: std::cell::RefCell::new(layout::ShellLayout::default()),
        }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn take_export_request(
        &mut self,
    ) -> Option<evertrace_protocol::dto::HumanGovernanceRequest> {
        if self.state.route != crate::Route::System
            || self.state.write_queued
            || self.state.export_selections.is_empty()
        {
            return None;
        }
        self.state.write_queued = true;
        self.state.export_result = None;
        self.state.export_pending = true;
        Some(evertrace_protocol::dto::HumanGovernanceRequest::Export {
            selections: self.state.export_selections.clone(),
        })
    }

    pub fn handle(&mut self, event: AppEvent) -> UiCommand {
        let event = match event {
            AppEvent::HumanRead {
                surface,
                locator:
                    HumanReadLocator::View {
                        generation,
                        request,
                    },
                response,
            } => {
                if generation != self.state.ui.read_generation {
                    return UiCommand::None;
                }
                AppEvent::HumanRead {
                    surface,
                    locator: *request,
                    response,
                }
            }
            AppEvent::HumanReadFailed {
                surface,
                locator:
                    HumanReadLocator::View {
                        generation,
                        request,
                    },
                code,
            } => {
                if generation != self.state.ui.read_generation {
                    return UiCommand::None;
                }
                AppEvent::HumanReadFailed {
                    surface,
                    locator: *request,
                    code,
                }
            }
            event => event,
        };
        if let AppEvent::Key(key) = &event {
            use crossterm::event::KeyEventKind;
            if key.kind == KeyEventKind::Release {
                return UiCommand::None;
            }
            if key.kind == KeyEventKind::Repeat
                && !matches!(
                    key.code,
                    KeyCode::Up
                        | KeyCode::Down
                        | KeyCode::Left
                        | KeyCode::Right
                        | KeyCode::Backspace
                        | KeyCode::Delete
                        | KeyCode::PageUp
                        | KeyCode::PageDown
                )
                && !(matches!(key.code, KeyCode::Char(_))
                    && !key.modifiers.contains(KeyModifiers::CONTROL)
                    && (self.state.proposal_edit.is_some() || self.state.ui.input.is_some()))
            {
                return UiCommand::None;
            }
        }
        match event {
            AppEvent::Mouse(mouse) => self.mouse(mouse),
            AppEvent::Paste(text) => {
                if is_config_editor(&self.state) && self.state.write_queued {
                    return UiCommand::None;
                }
                if let Some(edit) = &mut self.state.proposal_edit {
                    insert_edit_text(edit, &text);
                } else if self.state.ui.input.is_some() {
                    let text = text
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(512usize.saturating_sub(self.state.ui.query.len()))
                        .collect::<String>();
                    self.state
                        .ui
                        .query
                        .insert_str(self.state.ui.query_cursor, &text);
                    self.state.ui.query_cursor += text.len();
                    self.apply_query();
                }
                UiCommand::None
            }
            AppEvent::Key(key) if self.state.repository_purge_confirmation.is_some() => {
                self.handle_repository_purge_confirmation_key(key)
            }
            AppEvent::Key(key) if self.state.proposal_edit.is_some() => {
                self.handle_proposal_edit_key(key)
            }
            AppEvent::Key(key) => self.interaction_key(key),
            AppEvent::Health(health) => {
                self.state.shell.health = Some(health);
                self.state.shell.connection = ConnectionState::Connected;
                self.state.repository_purge_confirmation = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
                UiCommand::Refresh
            }
            AppEvent::ConfigDocument(document) => {
                if self.state.route == crate::Route::System && document.source.len() <= 128 * 1024 {
                    self.state.proposal_edit = Some(crate::state::ProposalEditState {
                        frozen_frontier: 0, // Config writes use only the file hash.
                        context: crate::state::ProposalEditContext::Configuration {
                            file_hash: document.file_hash,
                        },
                        document: document.source,
                        cursor: 0,
                        error: None,
                    });
                }
                UiCommand::None
            }
            AppEvent::ConfigApplied(result) => {
                if !matches!(
                    result.outcome,
                    evertrace_protocol::dto::ConfigReloadOutcome::Applied
                        | evertrace_protocol::dto::ConfigReloadOutcome::RestartRequired
                ) {
                    return self.handle(AppEvent::ConfigFailed);
                }
                self.state.write_queued = false;
                self.state.proposal_edit = None;
                self.state.detail_message = Some(crate::locale::format!(
                    self.state.language,
                    "configuration {:?}; pending={}",
                    "配置结果 {:?}；存在待应用配置={}",
                    result.outcome,
                    result.pending_hash.is_some()
                ));
                UiCommand::Refresh
            }
            AppEvent::ConfigFailed => {
                self.state.write_queued = false;
                if let Some(edit) = self.state.proposal_edit.as_mut() {
                    edit.error = Some(
                        self.state.language.text(
                            "configuration rejected or changed externally; reread before resubmitting",
                            "配置被拒绝或已被外部修改；请重新读取后再提交",
                        ).into(),
                    );
                }
                UiCommand::None
            }
            AppEvent::HumanReadFailed {
                surface,
                locator,
                code,
            } => {
                if (surface == human_surface(self.state.route)
                    || (matches!(locator, HumanReadLocator::Related { .. })
                        && related_locator_matches(&self.state, &locator)))
                    && (!matches!(locator, HumanReadLocator::Detail { .. })
                        || detail_locator_matches(&self.state, &locator))
                    && (!matches!(locator, HumanReadLocator::Related { .. })
                        || related_locator_matches(&self.state, &locator))
                {
                    if !matches!(code, crate::app_event::HumanReadFailure::Slow)
                        && matches!(locator, HumanReadLocator::Detail { .. })
                        && self.restore_failed_result()
                    {
                        return UiCommand::None;
                    }
                    if !matches!(code, crate::app_event::HumanReadFailure::Slow) {
                        self.state.ui.reading = false;
                        self.state.ui.read_finished = Some(std::time::Instant::now());
                    }
                    self.state.detail_message = Some(match code {
                        crate::app_event::HumanReadFailure::Rejected(code) => crate::locale::format!(self.state.language,
                            "Read failed: {code:?}; previous data retained", "读取失败：{code:?}；保留上次数据"),
                        crate::app_event::HumanReadFailure::Slow => self.state.language.text("Read is taking longer than expected; previous data retained; waiting for response", "读取耗时较长；保留上次数据，正在等待响应").into(),
                        crate::app_event::HumanReadFailure::TimedOut => self.state.language.text("Read timed out after 30 seconds; reconnecting", "读取超过 30 秒；正在重新连接").into(),
                    });
                }
                UiCommand::None
            }
            AppEvent::HumanRead {
                surface,
                locator,
                response: snapshot,
            } => {
                self.state.ui.reading = false;
                self.state.ui.read_finished = Some(std::time::Instant::now());
                if matches!(&locator, HumanReadLocator::Page { after } if self.state.ui.page_cursor.as_ref()!=Some(after))
                    || (matches!(locator, HumanReadLocator::List)
                        && self.state.ui.page_cursor.is_some())
                {
                    return UiCommand::None;
                }
                let locator = if matches!(locator, HumanReadLocator::Page { .. }) {
                    HumanReadLocator::List
                } else {
                    locator
                };
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
                self.state.ui.reading = false;
                self.state.ui.read_finished = Some(std::time::Instant::now());
                if self.modal_open() {
                    return UiCommand::None;
                }
                self.state.ui.read_at = Some(std::time::SystemTime::now());
                use evertrace_protocol::dto::HumanGovernanceResponse;
                match (locator, snapshot) {
                    (
                        HumanReadLocator::Related { .. },
                        snapshot @ HumanGovernanceResponse::Snapshot { .. },
                    ) => {
                        let previous = selected_item(&self.state).map(|i| i.stable_key.clone());
                        let next_selection = if self.state.ui.related_loaded {
                            match &snapshot {
                                HumanGovernanceResponse::Snapshot { items, .. } => previous
                                    .and_then(|key| items.iter().position(|i| i.stable_key == key))
                                    .unwrap_or(0),
                                _ => 0,
                            }
                        } else {
                            0
                        };
                        let item_count = match &snapshot {
                            HumanGovernanceResponse::Snapshot { items, .. } => items.len(),
                            _ => 0,
                        };
                        self.state.route = crate::Route::Explorer;
                        if !self.state.ui.related_loaded {
                            self.state.ui.filter.clear();
                            self.state.ui.list_offset = 0;
                            self.state.ui.type_filter = None;
                            self.state.ui.scope_filter = None;
                            self.state.ui.state_filter = None;
                        }
                        self.state.ui.related_loaded = true;
                        if let HumanGovernanceResponse::Snapshot { frontier, .. } = &snapshot
                            && let Some(context) = &mut self.state.related_context
                        {
                            context.expected_frontier = *frontier;
                        }
                        self.state.ui.focus = crate::state::Focus::List;
                        self.state.selection = next_selection;
                        self.state.human = Some(snapshot);
                        self.state.detail = None;
                        self.state.detail_message = (item_count == 0).then(|| self.state.language.text(
                            "No readable source/history entries were returned. Esc returns to the original object.",
                            "未返回可读取的来源／历史项。Esc 返回原对象。",
                        ).into());
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
                        let previous = selected_item(&self.state).map(|i| i.stable_key.clone());
                        let mut changed = false;
                        if let HumanGovernanceResponse::Snapshot { items, .. } = &snapshot {
                            self.state.selection = previous
                                .as_ref()
                                .and_then(|key| items.iter().position(|i| &i.stable_key == key))
                                .unwrap_or(self.state.selection.min(items.len().saturating_sub(1)));
                            if let Some(detail) = &self.state.detail
                                && !items.iter().any(|i| {
                                    i.stable_key == detail.stable_key
                                        && i.revision_ref == detail.revision_ref
                                })
                            {
                                self.state.detail = None;
                                changed = true;
                            }
                        }
                        self.state.human = Some(snapshot);
                        self.state.detail_message = changed.then(|| self.state.language.text(
                            "Selected object changed or disappeared; open its current detail before acting",
                            "所选对象已变化或消失；请先打开当前详情再操作",
                        ).into());
                        self.state.read_conflict = None;
                        let visible = views::visible_indices(&self.state);
                        if !visible.contains(&self.state.selection)
                            && let Some(index) = visible.first()
                        {
                            self.state.selection = *index;
                        }
                        if self.state.detail.is_some() {
                            UiCommand::Detail
                        } else {
                            UiCommand::None
                        }
                    }
                    (
                        HumanReadLocator::Detail { .. },
                        HumanGovernanceResponse::Snapshot {
                            mut items,
                            frontier,
                            status,
                            degraded_reasons,
                            diagnostics,
                            next_cursor,
                        },
                    ) => {
                        let first_open = self.state.detail.is_none();
                        let unreadable =
                            items.is_empty()
                                || items.iter().any(|item| {
                                    item.semantic_detail.as_ref().is_some_and(|detail| {
                                        matches!(detail.state,
                                evertrace_protocol::dto::HumanContentState::AccessDenied
                                | evertrace_protocol::dto::HumanContentState::Missing)
                                    })
                                });
                        if unreadable && self.restore_failed_result() {
                            return UiCommand::None;
                        }
                        if self.state.ui.reference_request.take().is_some() {
                            self.state.selection = 0;
                            self.state.human = Some(HumanGovernanceResponse::Snapshot {
                                diagnostics,
                                frontier,
                                status,
                                degraded_reasons,
                                items: items.clone(),
                                next_cursor,
                            });
                        }
                        self.state.detail = items.pop();
                        self.state.detail_frontier = self.state.detail.as_ref().map(|_| frontier);
                        if self.state.detail.as_ref().is_none_or(|i| {
                            i.semantic_detail.as_ref().is_some_and(|d| {
                                matches!(
                                    d.state,
                                    evertrace_protocol::dto::HumanContentState::AccessDenied
                                        | evertrace_protocol::dto::HumanContentState::Missing
                                )
                            })
                        }) {
                            self.state.ui.history.clear();
                        }
                        self.state.competing_candidate_selection = 0;
                        if first_open {
                            self.state.detail_scroll = 0;
                            self.state.ui.detail_view = crate::state::DetailView::Content;
                        }
                        self.state.ui.focus = crate::state::Focus::Detail;
                        self.state.detail_message = self.state.detail.is_none().then(|| self.state.language.text(
                            "The selected object has no readable detail in this view. Return to the list or refresh its current state.",
                            "所选对象在此视图没有可读详情。可返回列表，或刷新当前状态。",
                        ).into());
                        self.state.read_conflict = None;
                        UiCommand::None
                    }
                    (
                        HumanReadLocator::Related { .. },
                        HumanGovernanceResponse::Conflict {
                            current_frontier, ..
                        },
                    ) => {
                        self.state.read_conflict = Some(current_frontier);
                        self.state.detail_message = Some(self.state.language.text(
                            "Source/history read conflicted with changed data. Your selection is retained; return and refresh the source before opening it again.",
                            "来源／历史读取与数据变化冲突。已保留所选对象；请返回并刷新来源后重新打开。",
                        ).into());
                        UiCommand::None
                    }
                    (
                        HumanReadLocator::List,
                        HumanGovernanceResponse::Conflict {
                            current_frontier, ..
                        },
                    ) => {
                        self.state.ui.page_cursor = None;
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
                        if self.restore_failed_result() {
                            return UiCommand::None;
                        }
                        self.state.detail = None;
                        self.state.detail_scroll = 0;
                        self.state.proposal_confirmation = None;
                        self.state.read_conflict = Some(current_frontier);
                        self.state.detail_message = Some(current_revision_ref.map_or_else(
                            || crate::locale::format!(self.state.language,
                                "Detail read conflicted with changed data (frontier {current_frontier}); refresh the list and reopen the selected object.",
                                "详情读取与数据变化冲突（水位 {current_frontier}）；请刷新列表并重新打开所选对象。"),
                            |revision| {
                                crate::locale::format!(self.state.language,
                                    "The selected revision changed to {revision} (frontier {current_frontier}); refresh and review again before acting.",
                                    "所选修订已变为 {revision}（水位 {current_frontier}）；请刷新并重新审阅后再操作。")
                            },
                        ));
                        UiCommand::None
                    }
                    (
                        _,
                        HumanGovernanceResponse::Action { .. }
                        | HumanGovernanceResponse::Export { .. },
                    ) => UiCommand::None,
                    (HumanReadLocator::Page { .. } | HumanReadLocator::View { .. }, _) => {
                        UiCommand::None
                    }
                }
            }
            AppEvent::HumanAction(response) => {
                use evertrace_protocol::dto::{
                    HumanActionResult, HumanActionStatus, HumanGovernanceResponse,
                };
                let result = match response {
                    HumanGovernanceResponse::Export { result } => {
                        self.state.export_result = Some(result);
                        self.state.export_pending = false;
                        self.state.write_queued = false;
                        return UiCommand::None;
                    }
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
                self.state.proposal_edit = if matches!(
                    result.status,
                    HumanActionStatus::Conflict | HumanActionStatus::Unavailable
                ) {
                    self.state.ui.pending_edit.take().map(|mut edit| {
                        edit.error = Some(self.state.language.text(
                            "Action not applied; original target and draft retained. Reread before confirming.",
                            "操作未应用；已保留原目标和草稿。请重新读取后再确认。",
                        ).into());
                        edit
                    })
                } else {
                    self.state.ui.pending_edit = None;
                    None
                };
                self.state.proposal_confirmation = None;
                self.state.repository_purge_confirmation = None;
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
                self.state.ui.unknown_write |= self.state.write_queued;
                self.state.ui.reading = false;
                if self.state.export_pending {
                    self.state.export_result = Some(evertrace_protocol::dto::HumanExportResult {
                        status: evertrace_protocol::dto::HumanExportStatus::PublicationUncertain,
                        path: None,
                        frontier: 0,
                        object_count: self.state.export_selections.len() as u16,
                        total_bytes: 0,
                        reason: Some("connection_lost_inspect_exports_before_retrying".into()),
                    });
                    self.state.export_pending = false;
                }
                self.state.shell.connection = ConnectionState::Disconnected;
                if self.state.proposal_edit.is_none() {
                    self.state.proposal_edit = self.state.ui.pending_edit.take();
                }
                self.state.write_queued = false;
                self.state.proposal_confirmation = None;
                self.state.repository_purge_confirmation = None;
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
                self.state.repository_purge_confirmation = None;
                self.state.detail = None;
                self.state.detail_scroll = 0;
                self.state.recovery_selection = None;
                self.state.recovery_confirmation = None;
                self.state.related_context = None;
                self.state.future_operation_shell = None;
                UiCommand::None
            }
            AppEvent::Shutdown => self.dispatch(UiCommand::Quit),
            AppEvent::Resize(_, _) => {
                self.hit_regions.borrow_mut().clear();
                *self.visible_layout.borrow_mut() = layout::ShellLayout::default();
                UiCommand::None
            }
            AppEvent::Tick => {
                if !self.modal_open()
                    && self.state.ui.input.is_none()
                    && !self.state.ui.reading
                    && self.state.shell.pending == 0
                    && self.state.shell.connection == ConnectionState::Connected
                    && self
                        .state
                        .ui
                        .read_finished
                        .is_some_and(|t| t.elapsed() >= Duration::from_secs(5))
                {
                    self.state.ui.reading = true;
                    UiCommand::Refresh
                } else {
                    UiCommand::None
                }
            }
        }
    }

    fn handle_repository_purge_confirmation_key(&mut self, key: KeyEvent) -> UiCommand {
        if key.code == KeyCode::Esc {
            self.state.repository_purge_confirmation = None;
            return UiCommand::None;
        }
        let Some(confirmation) = self.state.repository_purge_confirmation.as_mut() else {
            return UiCommand::None;
        };
        match key.code {
            KeyCode::Backspace => {
                confirmation.entered_repository_id.pop();
                confirmation.error = None;
            }
            KeyCode::Char(value)
                if confirmation.entered_repository_id.len() < 64
                    && (value.is_ascii_alphanumeric() || matches!(value, '-' | ':')) =>
            {
                confirmation.entered_repository_id.push(value);
                confirmation.error = None;
            }
            KeyCode::Enter => {
                let exact_id = confirmation.entered_repository_id
                    == confirmation.preview.repository_id.to_string();
                if !exact_id {
                    confirmation.error = Some("repository_id_confirmation_mismatch".into());
                    return UiCommand::None;
                }
                if !confirmation.preview.blockers.is_empty() {
                    confirmation.error = Some("cross_scope_dependency_blocked".into());
                    return UiCommand::None;
                }
                let frontier = confirmation.frozen_frontier;
                let preview = confirmation.preview.clone();
                let action = evertrace_protocol::dto::HumanActionRequest::PurgeRepository {
                    repository_id: preview.repository_id,
                    repository_confirmation: confirmation.entered_repository_id.clone(),
                    expected_repository_revision: preview.repository_revision,
                    expected_deletion_generation: preview.deletion_generation,
                };
                self.state.repository_purge_confirmation = None;
                self.state.proposal_confirmation = Some((frontier, action, None));
                return UiCommand::ConfirmProposal;
            }
            _ => {}
        }
        UiCommand::None
    }

    fn handle_proposal_edit_key(&mut self, key: KeyEvent) -> UiCommand {
        if is_config_editor(&self.state) && self.state.write_queued {
            return UiCommand::None;
        }
        if key.code == KeyCode::Esc {
            self.state.proposal_edit = None;
            return UiCommand::None;
        }
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if is_config_editor(&self.state) {
                if !self.state.write_queued {
                    return UiCommand::SubmitConfig;
                }
                return UiCommand::None;
            }
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
        if matches!(
            command,
            UiCommand::Navigate(_)
                | UiCommand::NextPage
                | UiCommand::FirstPage
                | UiCommand::OpenRelated
                | UiCommand::OpenResult
                | UiCommand::OpenResultAt(_)
                | UiCommand::CancelModal
                | UiCommand::DetailView(crate::state::DetailView::History)
        ) {
            self.state.ui.read_generation = self.state.ui.read_generation.wrapping_add(1).max(1);
            self.state.ui.reading = false;
        }
        if !self.modal_open() {
            self.state.ui.confirmation_selected = false;
        }
        if command == UiCommand::Detail && self.state.repository_purge_confirmation.is_some() {
            return self.handle_repository_purge_confirmation_key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE,
            ));
        }
        if let Some(result) = self.ui_dispatch(command) {
            return result;
        }
        let command = if self.state.route == crate::Route::System {
            use evertrace_protocol::dto::RepositoryAccessAction;
            match command {
                UiCommand::OpenSupportDeprecateEditor => {
                    UiCommand::PrepareRepositoryAccess(RepositoryAccessAction::Disable)
                }
                UiCommand::OpenProposalEditor => {
                    UiCommand::PrepareRepositoryAccess(RepositoryAccessAction::Enable)
                }
                UiCommand::PrepareProposal(
                    evertrace_protocol::dto::ProposalHumanDecision::Reauthorize,
                ) => UiCommand::PrepareRepositoryAccess(RepositoryAccessAction::Rescan),
                _ => command,
            }
        } else {
            command
        };
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
                self.save_navigation(false);
                self.state.ui.page_cursor = None;
                self.state.ui.type_filter = None;
                self.state.ui.scope_filter = None;
                self.state.ui.state_filter = None;
                self.state.ui.reference_request = None;
                self.state.ui.filter.clear();
                self.state.ui.list_offset = 0;
                self.state.ui.focus = crate::state::Focus::List;
                self.state.ui.reading = true;
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
            UiCommand::OpenConfigEditor => {
                if self.state.route != crate::Route::System || self.state.write_queued {
                    return UiCommand::None;
                }
            }
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
                if self.state.route == crate::Route::System {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_add(1);
                }
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
                self.state.selection = self.state.selection.saturating_sub(1);
                if self.state.route == crate::Route::System {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_sub(1);
                }
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
                        evertrace_protocol::dto::ProposalHumanDecision::Reauthorize => {
                            "object_reauthorization_unavailable"
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
            UiCommand::PrepareForgetObject => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = forget_object_action(&self.state);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action = Some(local_unavailable("object_forget_unavailable"));
                }
            }
            UiCommand::PrepareRepositoryPurge => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.repository_purge_confirmation =
                    repository_purge_confirmation(&self.state);
                if self.state.repository_purge_confirmation.is_none() {
                    self.state.last_action =
                        Some(local_unavailable("repository_purge_unavailable"));
                }
            }
            UiCommand::PrepareRepositoryAccess(action) => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = repository_access_action(&self.state, action);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action =
                        Some(local_unavailable("select_repository_or_inventory_detail"));
                }
            }
            UiCommand::PrepareCreateBackup => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = create_backup_action(&self.state);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action = Some(local_unavailable("backup_create_unavailable"));
                }
            }
            UiCommand::ToggleExportSelection => {
                if self.state.route == crate::Route::Explorer
                    && let Some(item) =
                        self.state
                            .detail
                            .as_ref()
                            .or_else(|| match self.state.human.as_ref() {
                                Some(
                                    evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                                        items,
                                        ..
                                    },
                                ) => items.get(self.state.selection),
                                _ => None,
                            })
                {
                    let reference = item.stable_key.clone();
                    if let Some(index) = self
                        .state
                        .export_selections
                        .iter()
                        .position(|selected| selected.object_ref == reference)
                    {
                        self.state.export_selections.remove(index);
                    } else if self.state.export_selections.len() < 64 {
                        self.state.export_selections.push(
                            evertrace_protocol::dto::HumanExportSelection {
                                object_ref: reference,
                                expected_revision_ref: item.revision_ref.clone(),
                            },
                        );
                    }
                }
            }
            UiCommand::ExportSelection => {}
            UiCommand::PrepareCollectGarbage => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation =
                    create_backup_action(&self.state).map(|(frontier, _, review)| {
                        (
                            frontier,
                            evertrace_protocol::dto::HumanActionRequest::CollectGarbage,
                            review,
                        )
                    });
            }
            UiCommand::PrepareVerifyBackup => {
                if self.state.write_queued {
                    self.state.last_action = Some(local_transport_error());
                    return command;
                }
                self.state.proposal_confirmation = verify_backup_action(&self.state);
                if self.state.proposal_confirmation.is_none() {
                    self.state.last_action =
                        Some(local_unavailable("select_completed_backup_first"));
                }
            }
            UiCommand::OpenRelated => {
                self.save_navigation(false);
                self.state.ui.related_loaded = false;
                self.state.ui.page_cursor = None;
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
                self.state.ui.reading = true;
            }
            UiCommand::NextPage
            | UiCommand::FirstPage
            | UiCommand::Detail
            | UiCommand::ConfirmProposal
            | UiCommand::ConfirmRecovery
            | UiCommand::SubmitConfig
            | UiCommand::None => {}
            _ => {}
        }
        command
    }

    fn take_recovery_confirmation(
        &mut self,
    ) -> Option<evertrace_protocol::command::RequestRecoveryCommand> {
        self.state.recovery_confirmation.take()
    }

    pub fn render(&self, frame: &mut Frame) {
        self.render_shell(frame);
        if let Some(confirmation) = &self.state.repository_purge_confirmation {
            let area = centered(frame.area(), 76, 11);
            let (clear, modal) = components::modal(crate::locale::format!(
                self.state.language,
                "Repository purge\nExpected ID: {}\nRe-enter ID: {}\nPolicy: block_on_cross_scope_dependency\nStrict source erasure: unavailable\nBlockers: {:?}\n{}\nEnter confirms once; Esc cancels",
                "清除仓库\n预期 ID：{}\n重新输入 ID：{}\n策略：block_on_cross_scope_dependency\n严格擦除来源：不可用\n阻塞原因：{:?}\n{}\nEnter 确认一次；Esc 取消",
                confirmation.preview.repository_id,
                confirmation.entered_repository_id,
                confirmation.preview.blockers,
                confirmation.error.as_deref().unwrap_or(""),
            ));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some(edit) = &self.state.proposal_edit {
            let area = centered(
                frame.area(),
                76,
                frame.area().height.saturating_sub(2).min(18),
            );
            let (clear, modal) = components::modal(proposal_edit_modal_text(
                self.state.language,
                edit,
                area.width.saturating_sub(4) as usize,
                area.height.saturating_sub(5) as usize,
            ));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some(operation) = &self.state.future_operation_shell {
            let area = centered(frame.area(), 58, 11);
            let (clear, modal) =
                components::modal(future_operation_text(operation, self.state.language));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some(request) = &self.state.recovery_confirmation {
            let area = centered(frame.area(), 72, 6);
            let (clear, modal) = components::modal(crate::locale::format!(
                self.state.language,
                "Bundle: {}\nTarget Worktree: {}\nKind: {:?}\nEnter confirms once; Esc cancels",
                "恢复包：{}\n目标工作树：{}\n类型：{:?}\nEnter 确认一次；Esc 取消",
                request.recovery_bundle_id,
                request.target_worktree_instance_id,
                request.application_kind,
            ));
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        } else if let Some((_, action, review)) = &self.state.proposal_confirmation {
            let area = centered(
                frame.area(),
                76,
                frame.area().height.saturating_sub(3).min(20),
            );
            let review_tuple = review.as_ref().map_or_else(
                || self.state.language.text("Review: current closed action", "审阅：当前既有操作").into(),
                |review| {
                    crate::locale::format!(self.state.language,
                        "Proposal: {}\nRevision: {}\nFingerprint: {}\nFrozen candidate, scope and conditions:\n{}",
                        "提议：{}\n修订：{}\n指纹：{}\n已锁定的候选、范围与条件：\n{}",
                        review.proposal.proposal_id,
                        review.proposal.proposal_revision_id,
                        evertrace_domain::evidence::hex(&review.proposal.fingerprint),
                        evertrace_protocol::dto::proposal_payload_pretty_document(match action {evertrace_protocol::dto::HumanActionRequest::Proposal{edited_payload:Some(payload),..}=>payload.as_ref(),_=>&review.proposal.payload}).unwrap_or_else(|_|"Candidate cannot be displayed".into())
                    )
                },
            );
            let (clear, modal) = components::modal(crate::locale::format!(
                self.state.language,
                "Confirm {} once; Esc cancels\n{review_tuple}",
                "确认一次：{}；Esc 取消\n{review_tuple}",
                self.state.language.label(human_action_label(action))
            ));
            frame.render_widget(clear, area);
            frame.render_widget(
                modal
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((self.state.detail_scroll, 0)),
                area,
            );
        }
        if self.modal_open() {
            self.hit_regions.borrow_mut().clear();
            let area = Rect::new(
                frame.area().x,
                frame.area().bottom().saturating_sub(1),
                frame.area().width,
                1,
            );
            frame.render_widget(ratatui::widgets::Clear, area);
            let confirm = self.state.proposal_confirmation.is_some()
                || self.state.recovery_confirmation.is_some()
                || self.state.repository_purge_confirmation.is_some();
            let cancel = if confirm && !self.state.ui.confirmation_selected {
                self.state.language.text("[>Cancel] ", "[>取消] ")
            } else {
                self.state.language.text("[Cancel] ", "[取消] ")
            };
            let accept = if self.state.ui.confirmation_selected {
                self.state.language.text("[>Confirm once] ", "[>确认一次] ")
            } else {
                self.state.language.text("[Confirm once] ", "[确认一次] ")
            };
            let cancel_width = ratatui::text::Line::from(cancel).width() as u16;
            let accept_width = ratatui::text::Line::from(accept).width() as u16;
            frame.render_widget(
                Paragraph::new(format!(
                    "{cancel}{}{}",
                    if confirm { accept } else { "" },
                    if confirm {
                        self.state
                            .language
                            .text("Tab changes choice; ↑↓ scroll", "Tab 切换选择；↑↓ 滚动")
                    } else {
                        self.state.language.text("Esc closes", "Esc 关闭")
                    },
                )),
                area,
            );
            self.hit_regions.borrow_mut().push((
                Rect::new(area.x, area.y, area.width.min(cancel_width), 1),
                UiCommand::CancelModal,
            ));
            if confirm && area.width > cancel_width {
                self.hit_regions.borrow_mut().push((
                    Rect::new(
                        area.x + cancel_width,
                        area.y,
                        (area.width - cancel_width).min(accept_width),
                        1,
                    ),
                    UiCommand::Detail,
                ));
            }
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
            || review.reauthorization.is_some()
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
        crate::state::ProposalEditContext::Configuration { .. } => {
            return Err("configuration_requires_file_read");
        }
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
        frozen_frontier: action_frontier(state).unwrap_or(*frontier),
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
        frozen_frontier: action_frontier(state).unwrap_or(*frontier),
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

fn is_config_editor(state: &AppState) -> bool {
    state.proposal_edit.as_ref().is_some_and(|edit| {
        matches!(
            edit.context,
            crate::state::ProposalEditContext::Configuration { .. }
        )
    })
}

fn submit_proposal_edit(state: &mut AppState) {
    state.ui.confirmation_selected = false;
    let result = state
        .proposal_edit
        .as_ref()
        .ok_or_else(|| "proposal_editor_not_open".to_owned())
        .and_then(|edit| {
            let payload = evertrace_protocol::dto::parse_proposal_payload_document(&edit.document)
                .map_err(|error| format!("parse_error: {error}"))?;
            let original_payload = match &edit.context {
                crate::state::ProposalEditContext::Configuration { .. } => {
                    return Err("configuration_uses_file_hash".into());
                }
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
        crate::state::ProposalEditContext::Configuration { .. } => return,
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
    state.ui.pending_edit = state.proposal_edit.take();
}

fn insert_edit_text(edit: &mut crate::state::ProposalEditState, value: &str) -> bool {
    let limit = if matches!(
        edit.context,
        crate::state::ProposalEditContext::Configuration { .. }
    ) {
        128 * 1024
    } else {
        MAX_PROPOSAL_EDIT_DOCUMENT
    };
    if edit.document.len().saturating_add(value.len()) > limit {
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
    language: crate::Language,
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
        crate::state::ProposalEditContext::Configuration { .. } => language.text(
            "EDIT CONFIGURATION TOML (optimistic file hash)\n",
            "编辑配置 TOML（校验原文件哈希）\n",
        ),
        crate::state::ProposalEditContext::Proposal(_) => {
            language.text("EDIT PROPOSAL DOCUMENT\n", "编辑提议文档\n")
        }
        crate::state::ProposalEditContext::SupportReplacement { .. } => {
            language.text("EDIT SUPPORT REPLACEMENT\n", "编辑支持替换提议\n")
        }
        crate::state::ProposalEditContext::SupportDeprecate { .. } => {
            language.text("SUBMIT SUPPORT DEPRECATION\n", "提交支持弃用提议\n")
        }
    });
    rendered.push_str(language.text("Ctrl+S submit  Esc cancel\n", "Ctrl+S 提交  Esc 取消\n"));
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

fn future_operation_text(
    operation: &crate::state::FutureOperationShell,
    language: crate::Language,
) -> String {
    use crate::state::FutureOperationShell;
    match operation {
        FutureOperationShell::ForgetAtom(object_ref) => future_forget_text("Atom", object_ref, language),
        FutureOperationShell::ForgetProcedure(object_ref) => {
            future_forget_text("Procedure", object_ref, language)
        }
        FutureOperationShell::ForgetCoreMembership(object_ref) => {
            future_forget_text("Core membership", object_ref, language)
        }
        FutureOperationShell::Maintenance => language.text(
            "Restore is an offline operation.\nStop the daemon before running:\nevertrace restore BACKUP_PATH\nUse the configuration for the intended data directory.\nBackup, verification and orphan GC are available as jobs in System.\nThis notice sends no command.\nEsc returns.",
            "恢复是离线操作。\n先停止服务，再运行：\nevertrace restore BACKUP_PATH\n请使用目标数据目录对应的配置。\n备份、验证和孤立文件回收可在系统页提交任务。\n此说明不会发送命令。\nEsc 返回。",
        ).into(),
    }
}

fn future_forget_text(kind: &str, object_ref: &str, language: crate::Language) -> String {
    crate::locale::format!(
        language,
        "No authoritative daemon Forget preview for this object/state.\nObject kind: {kind}\nObject ID:\n{object_ref}\nObject Forget is not source erasure.\nNo affected counts or closure are available.\nNo space or support estimate is available.\nNo preview hash, token, or job ID exists.\nNo command will be sent.",
        "当前对象／状态没有服务端权威遗忘预览。\n对象类型：{kind}\n对象 ID：\n{object_ref}\n遗忘对象不等于擦除来源。\n未提供影响数量或闭包。\n没有空间或支持影响估算。\n不存在预览哈希、令牌或任务 ID。\n不会发送命令。"
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
    let app = App::with_language(crate::Language::English);
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
        terminal.draw(|frame| app.render(frame))?;
        loop {
            let Some(event) = receiver.recv().await else {
                return Ok::<(), io::Error>(());
            };
            let draw_needed = !matches!(event, AppEvent::Tick);
            let command = app.handle(event);
            if matches!(command, UiCommand::Navigate(_)) {
                let _ = ui_commands.try_send(client::ClientCommand::Refresh(
                    human_surface(app.state.route),
                    system_selection(&app.state),
                    if app.state.route == Route::Explorer {
                        app.state.ui.explorer_selection
                    } else {
                        None
                    },
                    app.state.ui.read_generation,
                ));
            }
            if let Some(request) = human_request(&app.state, command) {
                app.state.ui.reading = true;
                let command = match request {
                    evertrace_protocol::dto::HumanGovernanceRequest::Read { request } => {
                        client::ClientCommand::ReadView {
                            request,
                            generation: app.state.ui.read_generation,
                        }
                    }
                    request => client::ClientCommand::Human(request),
                };
                if ui_commands.try_send(command).is_err() {
                    app.state.ui.reading = false;
                    app.state.ui.read_finished = Some(std::time::Instant::now());
                    app.state.detail_message = Some(
                        app.state
                            .language
                            .text(
                                "Read could not be queued; retry reading",
                                "读取请求未能入队；请重试读取",
                            )
                            .into(),
                    );
                }
            }
            if command == UiCommand::OpenConfigEditor {
                let _ = ui_commands.try_send(client::ClientCommand::ConfigRead);
            }
            if command == UiCommand::SubmitConfig
                && let Some(edit) = &app.state.proposal_edit
                && let crate::state::ProposalEditContext::Configuration { file_hash } =
                    &edit.context
            {
                let request = evertrace_protocol::command::ConfigWriteCommand {
                    source: edit.document.clone(),
                    expected_file_hash: file_hash.clone(),
                };
                if request.source.len() <= 128 * 1024
                    && ui_commands
                        .try_send(client::ClientCommand::ConfigWrite(request))
                        .is_ok()
                {
                    app.state.write_queued = true;
                } else {
                    app.handle(AppEvent::ConfigFailed);
                }
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
            if command == UiCommand::ExportSelection
                && let Some(request) = app.take_export_request()
                && ui_commands
                    .try_send(client::ClientCommand::Human(request))
                    .is_err()
            {
                app.state.write_queued = false;
                app.state.export_pending = false;
                app.state.last_action = Some(local_transport_error());
            }
            if command == UiCommand::ConfirmProposal
                && let Some((expected_frontier, action, _)) =
                    app.state.proposal_confirmation.clone()
            {
                app.state.ui.action_submits_job = matches!(
                    action,
                    evertrace_protocol::dto::HumanActionRequest::CreateBackup
                        | evertrace_protocol::dto::HumanActionRequest::VerifyBackup { .. }
                        | evertrace_protocol::dto::HumanActionRequest::CollectGarbage
                        | evertrace_protocol::dto::HumanActionRequest::ForgetObject { .. }
                        | evertrace_protocol::dto::HumanActionRequest::PurgeRepository { .. }
                );
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
            if draw_needed || command != UiCommand::None {
                terminal.draw(|frame| app.render(frame))?;
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

fn system_selection(state: &AppState) -> Option<evertrace_protocol::dto::HumanSystemListSelection> {
    (state.route == crate::Route::System
        && matches!(
            state.ui.system_view,
            crate::state::SystemView::Overview | crate::state::SystemView::Jobs
        ))
    .then_some(evertrace_protocol::dto::HumanSystemListSelection::Jobs)
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
    if let Some((reference, frontier)) = &state.ui.reference_request {
        return reference == stable_key && frontier == expected_frontier;
    }
    let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. }) =
        state.human.as_ref()
    else {
        return false;
    };
    let Some(item) = selected_item(state) else {
        return false;
    };
    (frontier == expected_frontier
        || (current_detail(state).is_some()
            && state.detail_frontier.as_ref() == Some(expected_frontier)))
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
    } else if matches!(
        detail.object_kind.as_str(),
        "atom_revision" | "procedure_revision" | "core_membership"
    ) {
        evertrace_protocol::dto::HumanRelationKind::ObjectSources
    } else {
        return None;
    };
    Some(crate::state::RelatedContext {
        relation,
        source_stable_key: detail.stable_key.clone(),
        expected_source_revision_ref: detail.revision_ref.clone()?,
        expected_frontier: state.detail_frontier.unwrap_or(*frontier),
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
        UiCommand::Refresh => {
            if let Some(context) = &state.related_context {
                return Some(HumanGovernanceRequest::Read {
                    request: HumanReadRequest::Related {
                        relation: context.relation,
                        source_stable_key: context.source_stable_key.clone(),
                        expected_source_revision_ref: context.expected_source_revision_ref.clone(),
                        expected_frontier: context.expected_frontier,
                        after: state.ui.page_cursor.clone(),
                        limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                    },
                });
            }
            let expected_frontier = match &state.human {
                Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                    frontier,
                    ..
                }) if state.ui.page_cursor.is_some() => Some(*frontier),
                _ => None,
            };
            Some(HumanGovernanceRequest::Read {
                request: HumanReadRequest::List {
                    explorer_selection: (state.route == Route::Explorer)
                        .then_some(state.ui.explorer_selection)
                        .flatten(),
                    system_selection: system_selection(state),
                    surface,
                    expected_frontier,
                    after: state.ui.page_cursor.clone(),
                    limit: evertrace_protocol::dto::HUMAN_PAGE_LIMIT,
                },
            })
        }
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
                    explorer_selection: (state.route == Route::Explorer)
                        .then_some(state.ui.explorer_selection)
                        .flatten(),
                    system_selection: system_selection(state),
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
                    explorer_selection: (state.route == Route::Explorer)
                        .then_some(state.ui.explorer_selection)
                        .flatten(),
                    system_selection: system_selection(state),
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
            if let Some((reference, frontier)) = &state.ui.reference_request {
                return Some(HumanGovernanceRequest::Read {
                    request: HumanReadRequest::Detail {
                        surface,
                        object_ref: reference.clone(),
                        expected_frontier: *frontier,
                        expected_revision_ref: None,
                    },
                });
            }
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
        evertrace_protocol::dto::ProposalHumanDecision::Reauthorize => {
            let review = current_proposal_review(state)?;
            review.reauthorization.as_ref()?;
            Some(review.clone())
        }
        evertrace_protocol::dto::ProposalHumanDecision::Defer
        | evertrace_protocol::dto::ProposalHumanDecision::Reject => None,
    };
    Some((
        action_frontier(state).unwrap_or(*frontier),
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

/// A detail read may observe a later global frontier than its originating page.
/// Only actions on that exact selected detail may use it; page cursors remain pinned.
fn action_frontier(state: &AppState) -> Option<u64> {
    if current_detail(state).is_some()
        && let Some(frontier) = state.detail_frontier
    {
        return Some(frontier);
    }
    match state.human.as_ref()? {
        evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } => {
            Some(*frontier)
        }
        _ => None,
    }
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
        action_frontier(state).unwrap_or(*frontier),
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
        action_frontier(state).unwrap_or(*frontier),
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
        action_frontier(state).unwrap_or(*frontier),
        evertrace_protocol::dto::HumanActionRequest::MarkNewAttempt {
            expected_attempt_revision_id,
        },
        None,
    ))
}

fn forget_object_action(
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
    let preview = current_detail(state)?.forget_preview.as_ref()?;
    Some((
        action_frontier(state).unwrap_or(*frontier),
        evertrace_protocol::dto::HumanActionRequest::ForgetObject {
            target: preview.target,
            expected_revision_ids: preview.exact_revision_ids.clone(),
            expected_deletion_generation: preview.deletion_generation,
        },
        None,
    ))
}

fn repository_purge_confirmation(
    state: &AppState,
) -> Option<crate::state::RepositoryPurgeConfirmationState> {
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot { frontier, .. } =
        state.human.as_ref()?
    else {
        return None;
    };
    let preview = current_detail(state)?.repository_purge_preview.as_ref()?;
    Some(crate::state::RepositoryPurgeConfirmationState {
        frozen_frontier: action_frontier(state).unwrap_or(*frontier),
        preview: preview.as_ref().clone(),
        entered_repository_id: String::new(),
        error: None,
    })
}

fn create_backup_action(
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
    (state.route == crate::Route::System).then_some((
        action_frontier(state).unwrap_or(*frontier),
        evertrace_protocol::dto::HumanActionRequest::CreateBackup,
        None,
    ))
}

fn repository_access_action(
    state: &AppState,
    action: evertrace_protocol::dto::RepositoryAccessAction,
) -> Option<(
    u64,
    evertrace_protocol::dto::HumanActionRequest,
    Option<evertrace_protocol::dto::HumanProposalReview>,
)> {
    use evertrace_protocol::dto::{
        HumanActionRequest, HumanGovernanceResponse, HumanSystemDetail, RepositoryAccessAction,
    };
    if state.route != crate::Route::System {
        return None;
    }
    let HumanGovernanceResponse::Snapshot { frontier, .. } = state.human.as_ref()? else {
        return None;
    };
    let detail = current_detail(state)
        .or_else(|| selected_item(state))?
        .system_detail
        .as_ref()?;
    let (repository_id, expected_repository_revision, worktree_id, inventory_ref) = match detail {
        HumanSystemDetail::Repository {
            repository_id,
            repository_revision,
            worktree_id,
            ..
        } => (*repository_id, *repository_revision, *worktree_id, None),
        HumanSystemDetail::CapabilityInventory {
            job_id,
            repository_id,
            repository_revision,
            worktree_id,
            ..
        } => (
            *repository_id,
            *repository_revision,
            Some(*worktree_id),
            Some(*job_id),
        ),
        _ => return None,
    };
    let (worktree_id, inventory_ref) = if action == RepositoryAccessAction::Disable {
        (None, None)
    } else {
        (Some(worktree_id?), inventory_ref)
    };
    Some((
        action_frontier(state).unwrap_or(*frontier),
        HumanActionRequest::RepositoryAccess {
            repository_id,
            expected_repository_revision,
            action,
            worktree_id,
            inventory_ref,
        },
        None,
    ))
}

fn verify_backup_action(
    state: &AppState,
) -> Option<(
    u64,
    evertrace_protocol::dto::HumanActionRequest,
    Option<evertrace_protocol::dto::HumanProposalReview>,
)> {
    use evertrace_protocol::dto::{
        HumanActionRequest, HumanGovernanceResponse, HumanJobState, HumanSystemDetail,
    };
    let HumanGovernanceResponse::Snapshot { frontier, .. } = state.human.as_ref()? else {
        return None;
    };
    let HumanSystemDetail::Job { detail } = selected_item(state)?.system_detail.as_ref()? else {
        return None;
    };
    (state.route == crate::Route::System
        && detail.job_kind == "quiesced_backup_create_v1"
        && detail.state == HumanJobState::Succeeded)
        .then_some((
            action_frontier(state).unwrap_or(*frontier),
            HumanActionRequest::VerifyBackup {
                backup_job_id: detail.job_id,
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
            evertrace_protocol::dto::ProposalHumanDecision::Reauthorize => {
                "re-authorize forgotten object"
            }
        },
        HumanActionRequest::SupportReplacement { .. } => "submit support replacement",
        HumanActionRequest::SupportDeprecate { .. } => "submit support deprecate",
        HumanActionRequest::ResolveCompetingSelected { .. } => "select competing attempt",
        HumanActionRequest::MarkNewAttempt { .. } => "mark new attempt",
        HumanActionRequest::ForgetObject { .. } => "forget object",
        HumanActionRequest::PurgeRepository { .. } => "purge repository",
        HumanActionRequest::RepositoryAccess { action, .. } => match action {
            evertrace_protocol::dto::RepositoryAccessAction::Disable => "disable repository",
            evertrace_protocol::dto::RepositoryAccessAction::Enable => {
                "verify and enable repository"
            }
            evertrace_protocol::dto::RepositoryAccessAction::Rescan => {
                "rescan repository capabilities"
            }
        },
        HumanActionRequest::CreateBackup => "create quiesced backup",
        HumanActionRequest::CollectGarbage => {
            "collect orphan CAS (24 h grace) and prune versions older than 30 d"
        }
        HumanActionRequest::VerifyBackup { .. } => "verify backup",
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
            match event::poll(Duration::from_millis(250)) {
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
                    // Moves, releases and drags have no UI action. Do not queue
                    // them just to redraw an unchanged frame at mouse-event rate.
                    Ok(Event::Mouse(mouse))
                        if matches!(
                            mouse.kind,
                            event::MouseEventKind::Down(event::MouseButton::Left)
                                | event::MouseEventKind::ScrollDown
                                | event::MouseEventKind::ScrollUp
                        ) =>
                    {
                        let _ = events.blocking_send(AppEvent::Mouse(mouse));
                    }
                    Ok(Event::Paste(text)) => {
                        let _ = events.blocking_send(AppEvent::Paste(text));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let _ = events.blocking_send(AppEvent::Shutdown);
                        break;
                    }
                },
                Ok(false) => {
                    let _ = events.blocking_send(AppEvent::Tick);
                }
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

    #[test]
    fn export_disconnect_reports_unknown_and_does_not_retry() {
        let mut app = App::with_language(crate::Language::English);
        app.state.route = crate::Route::System;
        app.state
            .export_selections
            .push(evertrace_protocol::dto::HumanExportSelection {
                object_ref: "selected".into(),
                expected_revision_ref: None,
            });
        assert!(app.take_export_request().is_some());
        assert!(app.take_export_request().is_none());
        assert_eq!(app.handle(AppEvent::Disconnected), UiCommand::None);
        let result = app.state.export_result.as_ref().unwrap();
        assert_eq!(
            result.status,
            evertrace_protocol::dto::HumanExportStatus::PublicationUncertain
        );
        assert!(result.path.is_none());
        assert_eq!(
            result.reason.as_deref(),
            Some("connection_lost_inspect_exports_before_retrying")
        );
        let request = app.take_export_request().unwrap();
        app.handle(client::local_human_rejection(&request, "local_busy"));
        assert!(!app.state.export_pending);
        assert!(!app.state.write_queued);
        app.handle(AppEvent::Disconnected);
        let result = app.state.export_result.as_ref().unwrap();
        assert_eq!(
            result.status,
            evertrace_protocol::dto::HumanExportStatus::Failed
        );
        assert_eq!(result.reason.as_deref(), Some("local_busy"));
        assert!(result.path.is_none());
    }
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
        purge::ObjectDeletionTarget,
        repository::{
            GitRegistrationState, OrderingIntegrity, RecoveryCaptureStatus, WorktreeKind,
            WorktreeLifecycle,
        },
        revision::RevisionId,
        work::{
            CoverageLevel, LaneStatus, LivenessState, OrderingIntegrity as WorkOrderingIntegrity,
            PairingIntegrity, PayloadIntegrity, ReasoningVisibility, SourceCoverage,
        },
    };
    use evertrace_protocol::dto::{
        HealthMode, HumanBackupSummary, HumanBackupTableState, HumanBackupValidationResult,
        HumanCompetingDetail, HumanDegradedReason, HumanExecutionIntegrityDetail,
        HumanForgetPreview, HumanGovernanceResponse, HumanItemCategory, HumanItemKind,
        HumanJobBudget, HumanJobDetail, HumanJobState, HumanNegativeReviewMetadata,
        HumanObjectFamily, HumanProposalMetadata, HumanProposalReview, HumanRecoveryDetail,
        HumanRelationKind, HumanRepositoryPurgePreview, HumanRowClass, HumanSnapshotItem,
        HumanSnapshotStatus, HumanSurface, HumanSystemDetail, HumanWorktreeDetail,
        NegativeReviewDecision, PROTOCOL_VERSION, ProposalHumanDecision,
    };
    use evertrace_protocol::response::HealthResponse;

    #[test]
    fn configuration_editor_preserves_conflicted_document_and_uses_file_identity() {
        let mut app = App::with_language(crate::Language::English);
        app.state.route = crate::Route::System;
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Char('C'),
                KeyModifiers::NONE
            ))),
            UiCommand::OpenConfigEditor
        );
        app.handle(AppEvent::ConfigDocument(
            evertrace_protocol::response::ConfigDocumentResponse {
                source: "# preserved comment\nconfig_version = 1\n".into(),
                file_hash: "a".repeat(64),
            },
        ));
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('#'),
            KeyModifiers::NONE,
        )));
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Char('s'),
                KeyModifiers::CONTROL
            ))),
            UiCommand::SubmitConfig
        );
        let document = app.state.proposal_edit.as_ref().unwrap().document.clone();
        app.state.write_queued = true;
        app.handle(AppEvent::Paste(
            "must not alter the submitted document".into(),
        ));
        assert_eq!(app.state.proposal_edit.as_ref().unwrap().document, document);
        app.handle(AppEvent::ConfigApplied(
            evertrace_protocol::response::ConfigReloadResponse {
                active_hash: [0; 32],
                pending_hash: None,
                outcome: evertrace_protocol::dto::ConfigReloadOutcome::Rejected,
            },
        ));
        let edit = app.state.proposal_edit.as_ref().unwrap();
        assert_eq!(edit.document, document);
        assert!(edit.error.is_some());
        assert!(
            matches!(&edit.context, crate::state::ProposalEditContext::Configuration { file_hash } if file_hash == &"a".repeat(64))
        );
        assert!(!app.state.write_queued);
    }

    #[test]
    fn repository_purge_requires_exact_id_and_never_offers_strict_erasure() {
        let repository_id = RepositoryId::new_v7();
        let mut item = snapshot_item("repository", repository_id.to_string());
        item.category = HumanItemCategory::Repository;
        item.repository_purge_preview = Some(Box::new(HumanRepositoryPurgePreview {
            repository_id,
            repository_revision: 1,
            deletion_generation: 2,
            planned_exclusive_cas_count: 3,
            shared_cas_retained_count: 1,
            repository_derived_global_dependency_count: 1,
            affected_session_count: 0,
            affected_evidence_receipt_capture_count: 0,
            affected_work_count: 0,
            affected_atom_count: 0,
            affected_procedure_count: 0,
            affected_experiment_run_count: 0,
            affected_result_evidence_count: 0,
            affected_artifact_count: 0,
            affected_recovery_count: 0,
            affected_recall_derived_count: 0,
            relationship_only_count: 0,
            estimated_reclaimable_bytes: None,
            blockers: vec![
                evertrace_domain::purge::RepositoryPurgeBlocker::RepositoryDerivedGlobalDependency,
            ],
            downstream_support_revalidation_count: 0,
            dependent_procedure_review_hold_count: 0,
        }));
        let mut app = App::with_language(crate::Language::English);
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            diagnostics: None,
            frontier: 9,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![item.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(item);
        app.state.detail_frontier = None;
        app.dispatch(UiCommand::PrepareRepositoryPurge);
        assert!(app.state.proposal_confirmation.is_none());
        for value in repository_id.to_string().chars() {
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Char(value),
                KeyModifiers::NONE,
            )));
        }
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            ))),
            UiCommand::None
        );
        assert!(app.state.proposal_confirmation.is_none());
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::F(3),
            KeyModifiers::NONE,
        )));
        assert!(
            !app.state
                .repository_purge_confirmation
                .as_ref()
                .unwrap()
                .preview
                .blockers
                .is_empty()
        );
        assert_eq!(
            app.state
                .repository_purge_confirmation
                .as_ref()
                .unwrap()
                .entered_repository_id,
            repository_id.to_string()
        );
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            ))),
            UiCommand::None
        );
        app.state
            .repository_purge_confirmation
            .as_mut()
            .unwrap()
            .preview
            .blockers
            .clear();
        assert_eq!(
            app.handle(AppEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            ))),
            UiCommand::ConfirmProposal
        );
        assert!(matches!(
            app.state.proposal_confirmation.as_ref(),
            Some((9, evertrace_protocol::dto::HumanActionRequest::PurgeRepository {
                repository_id: actual,
                repository_confirmation,
                expected_repository_revision: 1,
                expected_deletion_generation: 2,
            }, None)) if *actual == repository_id && repository_confirmation == &repository_id.to_string()
        ));
    }

    #[test]
    fn system_backup_actions_use_the_existing_confirmation_path() {
        let backup_job_id = JobId::new_v7();
        let mut item = snapshot_item("runtime_event", "backup".into());
        item.stable_key = format!("runtime:job:{backup_job_id}");
        item.row_class = HumanRowClass::Runtime;
        item.family = HumanObjectFamily::Runtime;
        item.category = HumanItemCategory::Runtime;
        item.object_ref = None;
        item.system_detail = Some(HumanSystemDetail::Job {
            detail: Box::new(HumanJobDetail {
                job_id: backup_job_id,
                target_revision: format!("backup:{backup_job_id}"),
                target_watermark: 9,
                target_generation: 1,
                job_kind: "quiesced_backup_create_v1".into(),
                algorithm_revision: "quiesced_backup_v1".into(),
                model_id: None,
                priority: 1,
                state: HumanJobState::Succeeded,
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
                terminal_reason: Some(evertrace_protocol::dto::HumanJobTerminalReason::Completed),
                terminal_result_ref: Some(format!("backup:{backup_job_id}")),
                gc_summary: None,
                native_history_cleanup_availability: None,
                backup_summary: Some(HumanBackupSummary {
                    frontier: 9,
                    journal: HumanBackupTableState {
                        version: 4,
                        frontier: 9,
                    },
                    objects: HumanBackupTableState {
                        version: 5,
                        frontier: 9,
                    },
                    relations: Some(HumanBackupTableState {
                        version: 6,
                        frontier: 6,
                    }),
                    search: Some(HumanBackupTableState {
                        version: 7,
                        frontier: 7,
                    }),
                    committed_source_watermark_count: 2,
                    spool_source_watermark_count: 1,
                    live_cas_count: 3,
                    spool_cas_count: 1,
                    spool_file_count: 1,
                    spool_generation_count: 1,
                    normal_spool_frame_count: 1,
                    isolated_spool_frame_count: 0,
                    emergency_gap_count: 0,
                    quarantine_count: 0,
                    runtime_outbox_watermark: 8,
                    index_generation: 1,
                    compiler_watermark: 9,
                    effective_config_hash: [8; 32],
                    runtime_generation: 3,
                    hook_current_generation: Some(2),
                    hook_retained_generations: vec![1, 2],
                    hook_pin_count: 1,
                    session_pinned_hook_artifact_count: 1,
                    object_deletion_generation: 4,
                    repository_purge_generation: 5,
                    file_count: 12,
                    total_bytes: 4096,
                    required_space_bytes: 8192,
                    available_space_bytes_at_preflight: 16384,
                    validation_result: HumanBackupValidationResult::VerifiedBeforePublish,
                }),
            }),
        });
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::System));
        app.handle(AppEvent::Health(HealthResponse {
            protocol_version: PROTOCOL_VERSION,
            mode: HealthMode::Normal,
            config_version: 1,
            effective_config_hash: "0".repeat(64),
            algorithm_revision: 1,
            host_canary: Some(evertrace_protocol::dto::HostCanaryDiagnostic {
                qualification: None,
                scope: evertrace_protocol::dto::HostCanaryScope::Installed,
                status: evertrace_protocol::dto::HostCanaryStatus::EvidenceMissing,
                native_delivery_observed: true,
                mcp_claim_consumed: false,
                capture_receipt_observed: false,
            }),
        }));
        let current = render_app(&app, 100, 50);
        for label in [
            "Host canary: EvidenceMissing",
            "CaptureReceipt: false",
            "Last Health:",
        ] {
            assert!(current.contains(label), "missing {label}");
        }
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            diagnostics: None,
            frontier: 9,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![item],
            next_cursor: None,
        });

        app.dispatch(UiCommand::PrepareCreateBackup);
        assert!(matches!(
            app.state.proposal_confirmation.take(),
            Some((
                9,
                evertrace_protocol::dto::HumanActionRequest::CreateBackup,
                None
            ))
        ));
        app.dispatch(UiCommand::PrepareCollectGarbage);
        assert!(matches!(
            app.state.proposal_confirmation.take(),
            Some((
                9,
                evertrace_protocol::dto::HumanActionRequest::CollectGarbage,
                None
            ))
        ));
        app.dispatch(UiCommand::PrepareVerifyBackup);
        assert!(matches!(
            app.state.proposal_confirmation.take(),
            Some((
                9,
                evertrace_protocol::dto::HumanActionRequest::VerifyBackup { backup_job_id: id },
                None
            )) if id == backup_job_id
        ));
        app.state.detail = selected_item(&app.state).cloned();
        app.state.detail_frontier = None;
        app.state.ui.detail_view = crate::state::DetailView::Technical;
        let rendered = render_app(&app, 160, 100);
        assert!(rendered.contains("backup verification/frontier: VerifiedBeforePublish / 9"));
        for table in ["v4@9", "v5@9", "v6@6", "v7@7"] {
            assert!(rendered.contains(table));
        }
        assert!(rendered.contains("backup hook current/retained: 2/2"));
        assert!(rendered.contains("backup hook pins/pinned artifacts: 1/1"));
    }

    #[test]
    fn recovery_requires_explicit_bundle_target_and_one_confirmation() {
        let bundle_one = RecoveryBundleId::new_v7();
        let bundle_two = RecoveryBundleId::new_v7();
        let worktree_one = WorktreeId::new_v7();
        let worktree_two = WorktreeId::new_v7();
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::Explorer));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
        app.state.detail_frontier = None;
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
        app.state.detail_frontier = None;
        assert!(render_app(&app, 100, 30).contains("Registered"));
        worktree_detail.recovery_detail = bundle_detail.recovery_detail;
        assert!(
            !HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
                diagnostics: None,
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
        app.state.detail_frontier = None;
        let rendered = render_app(&app, 100, 30);
        assert!(rendered.contains("lane/revision"));
        assert!(rendered.contains(&lane_id.to_string()));
        let valid_lane_detail = lane_detail.clone();
        lane_detail.object_kind = "capture_receipt".into();
        assert!(
            !HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
                diagnostics: None,
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
                backup_summary: None,
                gc_summary: None,
                native_history_cleanup_availability: Some(evertrace_protocol::dto::HumanNativeHistoryCleanupAvailability::ExternalReaderExclusionUnverified),
            }),
        });
        app.state.detail = Some(job_detail.clone());
        app.state.detail_frontier = None;
        app.state.ui.detail_view = crate::state::DetailView::Content;
        app.state.language = crate::Language::Chinese;
        let chinese_job = views::detail_text(&app.state);
        assert!(chinese_job.contains("任务：重建对象索引\n状态：排队中"));
        assert!(chinese_job.contains("退避截止：未提供"));
        assert!(chinese_job.contains("object:target"));
        assert!(!chinese_job.contains("objects_projection"));
        let mut occurrence = snapshot_item("host_occurrence", "occ:unchanged".into());
        occurrence.lifecycle = Some("immutable".into());
        let chinese_occurrence = views::row_label(&occurrence, crate::Language::Chinese);
        assert!(chinese_occurrence.contains("宿主事件"));
        assert!(chinese_occurrence.contains("不可变记录"));
        assert!(chinese_occurrence.contains("occ:unchanged"));
        assert_eq!(
            views::kind_label("semantic_synthesis_v1", crate::Language::Chinese),
            "生成语义摘要"
        );
        assert_eq!(
            views::status_label("Succeeded", crate::Language::Chinese),
            "已结束"
        );
        app.state.language = crate::Language::English;
        app.state.ui.detail_view = crate::state::DetailView::Technical;
        let rendered = render_app(&app, 100, 30);
        assert!(rendered.contains(&job_id.to_string()));
        assert!(rendered.contains("objects_projection"));
        assert!(rendered.contains("Native history cleanup: unavailable now"));
        assert!(
            views::detail_text(&app.state).contains("External reader exclusion is unverified.")
        );
        for language in [crate::Language::English, crate::Language::Chinese] {
            for outcome in 0..4 {
                let mut jump = App::with_language(language);
                jump.dispatch(UiCommand::Navigate(crate::Route::System));
                let mut job = job_detail.clone();
                if let Some(HumanSystemDetail::Job { detail }) = &mut job.system_detail {
                    detail.terminal_result_ref = Some("obs:result".into());
                }
                jump.state.human = Some(HumanGovernanceResponse::Snapshot {
                    diagnostics: None,
                    frontier: 7,
                    status: HumanSnapshotStatus::Ready,
                    degraded_reasons: vec![],
                    items: vec![job.clone(), job.clone()],
                    next_cursor: Some("runtime:job:next".into()),
                });
                jump.state.detail = Some(job);
                jump.state.selection = 1;
                jump.state.ui.page_cursor = Some("runtime:job:previous".into());
                jump.state.ui.list_offset = 1;
                jump.state.ui.filter = "original job filter".into();
                jump.state.ui.type_filter = Some("runtime_event".into());
                jump.state.detail_scroll = 3;
                let original = jump.state.human.clone();
                assert_eq!(jump.dispatch(UiCommand::OpenResult), UiCommand::Detail);
                assert!(jump.state.human.is_none());
                assert!(jump.state.ui.page_cursor.is_none());
                assert!(jump.state.ui.filter.is_empty());
                assert!(jump.state.ui.type_filter.is_none());
                let locator = HumanReadLocator::View {
                    generation: jump.state.ui.read_generation,
                    request: Box::new(HumanReadLocator::Detail {
                        expected_frontier: 7,
                        stable_key: "obs:result".into(),
                        expected_revision_ref: None,
                    }),
                };
                if outcome < 2 {
                    jump.handle(AppEvent::HumanRead {
                        surface: HumanSurface::Explorer,
                        locator,
                        response: HumanGovernanceResponse::Snapshot {
                            diagnostics: None,
                            frontier: 7,
                            status: HumanSnapshotStatus::Ready,
                            degraded_reasons: vec![],
                            next_cursor: None,
                            items: if outcome == 0 {
                                vec![snapshot_item("source_observation", "obs:result".into())]
                            } else {
                                vec![]
                            },
                        },
                    });
                    if outcome == 0 {
                        jump.dispatch(UiCommand::CancelModal);
                    }
                } else {
                    jump.handle(AppEvent::HumanReadFailed {
                        surface: HumanSurface::Explorer,
                        locator,
                        code: if outcome == 2 {
                            crate::app_event::HumanReadFailure::Rejected(
                                evertrace_protocol::error::ErrorCode::InvalidInput,
                            )
                        } else {
                            crate::app_event::HumanReadFailure::TimedOut
                        },
                    });
                }
                assert_eq!(jump.state.route, crate::Route::System);
                assert_eq!(jump.state.human, original);
                assert_eq!(jump.state.selection, 1);
                assert_eq!(jump.state.ui.list_offset, 1);
                assert_eq!(jump.state.ui.filter, "original job filter");
                assert_eq!(jump.state.ui.type_filter.as_deref(), Some("runtime_event"));
                assert_eq!(jump.state.detail_scroll, 3);
                assert_eq!(
                    jump.state.ui.page_cursor.as_deref(),
                    Some("runtime:job:previous")
                );
                if outcome != 0 {
                    assert!(jump.state.detail_message.is_some());
                }
                if outcome == 0 {
                    jump.dispatch(UiCommand::CancelModal);
                    assert!(jump.state.detail.is_none());
                    jump.dispatch(UiCommand::Navigate(crate::Route::Explorer));
                    let host = snapshot_item("host_occurrence", "occ:ordinary".into());
                    jump.state.human = Some(HumanGovernanceResponse::Snapshot {
                        diagnostics: None,
                        frontier: 7,
                        status: HumanSnapshotStatus::Ready,
                        degraded_reasons: vec![],
                        items: vec![host.clone()],
                        next_cursor: None,
                    });
                    jump.state.detail = Some(host);
                    jump.dispatch(UiCommand::CancelModal);
                    assert_eq!(jump.state.route, crate::Route::Explorer);
                    assert!(jump.state.detail.is_none());
                    jump.dispatch(UiCommand::CancelModal);
                    assert_eq!(jump.state.route, crate::Route::System);
                    assert_eq!(jump.state.human, original);
                }
            }
        }
        let mut forged = job_detail.clone();
        forged.stable_key = "runtime:job:forged".into();
        assert!(
            !HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
                diagnostics: None,
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
            source_context: None,
            semantic_detail: None,
            proposal_base: None,
            evidence_detail: None,
            work_detail: None,
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
            forget_preview: None,
            repository_purge_preview: None,
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
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::Inbox));
        app.handle(AppEvent::Health(HealthResponse {
            protocol_version: PROTOCOL_VERSION,
            mode: HealthMode::Normal,
            config_version: 1,
            effective_config_hash: "0".repeat(64),
            algorithm_revision: 1,
            host_canary: None,
        }));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
            reauthorization: None,
            capability_coverage: None,
        });
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::Detail {
                expected_frontier: 9,
                stable_key: "proposal-row".into(),
                expected_revision_ref: Some(revision_id.to_string()),
            },
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 9,
                status: HumanSnapshotStatus::Degraded,
                degraded_reasons: vec![HumanDegradedReason::CurrentJobFailed],
                items: vec![detail_item],
                next_cursor: None,
            },
        });
        let compact = render_app(&app, 60, 20);
        assert!(compact.contains("Esc back"));
        app.state.detail_scroll = 0;
        let wide = render_app(&app, 120, 36);
        assert!(wide.contains("keep the reviewed invariant"));
        assert!(views::detail_text(&app.state).contains("Repository"));
        assert!(wide.contains("exact base") || wide.contains("no base"));
        assert!(compact.contains("Detail"));
        let english_request = human_request(&app.state, UiCommand::Detail);
        app.dispatch(UiCommand::Language(crate::Language::Chinese));
        let chinese = render_app(&app, 80, 24);
        assert!(chinese.contains('详') && chinese.contains('情'));
        assert!(chinese.contains("keep the reviewed invariant"));
        assert_eq!(
            human_request(&app.state, UiCommand::Detail),
            english_request
        );
        app.dispatch(UiCommand::Language(crate::Language::English));
        {
            use evertrace_domain::semantic::{
                CoreMembership, CoreMembershipProposalPayload, CoreScopeIdentity,
            };
            use evertrace_protocol::dto::{
                HumanContentState, HumanSemanticContent, HumanSemanticDetail,
            };
            let mut comparison = app.state.clone();
            let detail = comparison.detail.as_mut().unwrap();
            let proposal = &mut detail.proposal_review.as_mut().unwrap().proposal;
            proposal.operation = ProposalOperation::Replace;
            proposal.payload = ProposalPayload::CoreMembership(Box::new(
                CoreMembershipProposalPayload::ResolveConflict {
                    left_atom_revision_id: revision_id,
                    right_atom_revision_id: evertrace_domain::revision::RevisionId::new_v7(),
                    scope_identity: CoreScopeIdentity::Repository(repository_id),
                },
            ));
            detail.proposal_base = Some(HumanSemanticDetail {
                object_ref: None,
                revision_ref: Some(revision_id.to_string()),
                state: HumanContentState::Ready,
                preview: None,
                original_bytes: 0,
                content: Some(HumanSemanticContent::CoreMembership(Box::new(
                    CoreMembership {
                        core_membership_id: evertrace_domain::ids::CoreMembershipId::new_v7(),
                        membership_revision_id: revision_id,
                        atom_revision_id: revision_id,
                        scope_identity: CoreScopeIdentity::Global,
                        support_contract_ref: revision_id,
                        authorization_revision_refs: vec![revision_id],
                        supersedes_membership_revision_id: None,
                        created_by_acceptance_ref: revision_id,
                        active: true,
                    },
                ))),
            });
            let text = views::detail_text(&comparison);
            assert!(text.contains("exact base → candidate"));
            assert!(text.contains("Conflict right atom revision"));
            assert!(!text.contains("Conflict left atom revision"));
            assert!(text.contains("Scope identity\n  Global\n→ Repository"));
            assert!(!text.contains("Membership change:"));
        }
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
            diagnostics: None,
            frontier: 11,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![support_item.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(support_item.clone());
        app.state.detail_frontier = None;
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
        app.state.detail_frontier = None;
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
        app.state.detail_frontier = None;
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
            reauthorization: None,
            capability_coverage: None,
        });
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            diagnostics: None,
            frontier: 10,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![merge_item.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(merge_item);
        app.state.detail_frontier = None;
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
                diagnostics: None,
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
        let mut source = selected_item(&app.state).unwrap().clone();
        source.evidence_detail = Some(evertrace_protocol::dto::HumanEvidenceDetail {
            source_kind: evertrace_domain::evidence::EvidenceSourceKind::CodexHook,
            observation_role: evertrace_domain::evidence::ObservationRole::Message,
            source_role: evertrace_domain::evidence::SourceRole::Host,
            content_trust: evertrace_domain::evidence::ContentTrust::Observed,
            capture_completeness: evertrace_domain::evidence::CaptureCompleteness::Partial,
            protected_presentation: Some(
                evertrace_domain::evidence::ProtectedPresentation::Preview {
                    text: "Keep this source text / 保留原始正文".into(),
                },
            ),
            protected_length: 64,
            cas_ref: "a".repeat(64),
        });
        let source_locator = HumanReadLocator::Detail {
            expected_frontier: 10,
            stable_key: source.stable_key.clone(),
            expected_revision_ref: source.revision_ref.clone(),
        };
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: source_locator,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 10,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![source],
                next_cursor: None,
            },
        });
        for language in [crate::Language::Chinese, crate::Language::English] {
            app.dispatch(UiCommand::Language(language));
            assert!(render_app(&app, 80, 24).contains("Keep this source text"));
        }
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.detail.is_none());
        assert!(app.state.related_context.is_some());
        app.dispatch(UiCommand::CancelModal);
        assert_eq!(app.state.route, crate::Route::Inbox);
        assert_eq!(
            app.state.detail.as_ref().unwrap().stable_key,
            "proposal-row"
        );
        assert!(app.state.proposal_confirmation.is_none());
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
            diagnostics: None,
            frontier: 11,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![atom.clone()],
            next_cursor: None,
        });
        app.state.detail = Some(atom);
        app.state.detail_frontier = None;
        app.dispatch(UiCommand::OpenFutureOperationShell);
        assert!(matches!(
            app.state.future_operation_shell.as_ref(),
            Some(crate::state::FutureOperationShell::ForgetAtom(object_ref))
                if object_ref == &atom_id.to_string()
        ));
        assert!(human_request(&app.state, UiCommand::OpenFutureOperationShell).is_none());
        let forget = render_app(&app, 60, 20);
        assert!(forget.contains(&atom_id.to_string()));
        assert!(forget.contains("No authoritative daemon Forget preview"));
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
        let system = render_app(&app, 60, 20);
        assert!(system.contains("Hook: not observed"));
        assert!(system.contains("Queued"));
        app.dispatch(UiCommand::OpenFutureOperationShell);
        assert!(human_request(&app.state, UiCommand::OpenFutureOperationShell).is_none());
        let maintenance = render_app(&app, 60, 20);
        assert!(maintenance.contains("offline operation"));
        assert!(maintenance.contains("evertrace restore BACKUP_PATH"));
        assert!(maintenance.contains("Backup, verification and orphan GC"));
        assert!(maintenance.contains("This notice sends no command"));
        assert!(app.state.proposal_confirmation.is_none());
        assert!(app.state.recovery_confirmation.is_none());
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::None);
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.future_operation_shell.is_none());
    }

    #[test]
    fn stale_surface_read_is_ignored_without_refresh() {
        let mut app = App::with_language(crate::Language::English);
        let command = app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
            diagnostics: None,
            frontier: 7,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![item.clone()],
            next_cursor: None,
        };
        assert!(snapshot.validate());
        let mut app = App::with_language(crate::Language::English);
        app.state.human = Some(snapshot);
        app.state.detail = Some(item);
        app.state.detail_frontier = None;

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
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::Inbox));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
    fn explorer_forget_uses_only_the_daemon_preview_and_one_confirmation() {
        let atom_id = AtomId::new_v7();
        let revision_id = RevisionId::new_v7();
        let target = ObjectDeletionTarget::Atom { atom_id };
        let mut item = snapshot_item("atom_revision", target.object_ref());
        item.family = HumanObjectFamily::Atom;
        item.category = HumanItemCategory::Semantic;
        item.revision_ref = Some(revision_id.to_string());
        item.forget_preview = Some(Box::new(HumanForgetPreview {
            target,
            current_revision_id: revision_id,
            exact_revision_ids: vec![revision_id],
            deletion_generation: 3,
            shared_source_count: 1,
            suppressed_source_count: 2,
            suppression_ref_count: 4,
            downstream_support_revalidation_count: 1,
            dependent_procedure_review_hold_count: 1,
        }));
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::Explorer));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Explorer,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 12,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![item.clone()],
                next_cursor: None,
            },
        });
        app.state.detail = Some(item);
        app.state.detail_frontier = None;
        app.dispatch(UiCommand::PrepareForgetObject);
        assert!(matches!(
            app.state.proposal_confirmation,
            Some((
                12,
                evertrace_protocol::dto::HumanActionRequest::ForgetObject {
                    target: ObjectDeletionTarget::Atom { atom_id: selected },
                    ref expected_revision_ids,
                    expected_deletion_generation: 3,
                },
                None,
            )) if selected == atom_id && expected_revision_ids == &[revision_id]
        ));
        assert_eq!(app.dispatch(UiCommand::Detail), UiCommand::ConfirmProposal);
        app.dispatch(UiCommand::CancelModal);
        assert!(app.state.proposal_confirmation.is_none());
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
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::Inbox));
        app.handle(AppEvent::HumanRead {
            surface: evertrace_protocol::dto::HumanSurface::Inbox,
            locator: HumanReadLocator::List,
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
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
                diagnostics: None,
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
        let mut disconnected = App::with_language(crate::Language::English);
        disconnected.handle(AppEvent::Disconnected);
        assert!(render_app(&disconnected, 100, 30).contains("Daemon disconnected"));

        let mut stopping = App::with_language(crate::Language::English);
        stopping.handle(AppEvent::Notification(
            evertrace_protocol::notification::Notification::ServerStopping,
        ));
        assert!(render_app(&stopping, 100, 30).contains("Daemon stopping; read unavailable"));
    }

    #[test]
    fn submitted_evidence_detail_is_authority_free_and_control_safe() {
        use evertrace_domain::evidence::{
            CaptureCompleteness, ContentTrust, EvidenceSourceKind, ObservationRole,
            ProtectedPresentation, SourceRole,
        };
        let mut app = App::with_language(crate::Language::English);
        app.state.route = crate::Route::Explorer;
        let mut item = snapshot_item("source_receipt", "receipt-test".into());
        assert!(
            !String::from_utf8(evertrace_protocol::frame::canonical_json(&item).unwrap())
                .unwrap()
                .contains("evidence_detail")
        );
        item.evidence_detail = Some(evertrace_protocol::dto::HumanEvidenceDetail {
            source_kind: EvidenceSourceKind::CodexHook,
            observation_role: ObservationRole::Message,
            source_role: SourceRole::Host,
            content_trust: ContentTrust::Observed,
            capture_completeness: CaptureCompleteness::Partial,
            protected_presentation: Some(ProtectedPresentation::Preview {
                text: "submitted \u{1b}[31m".into(),
            }),
            protected_length: 100,
            cas_ref: "a".repeat(64),
        });
        app.state.detail = Some(item);
        app.state.detail_frontier = None;
        let rendered = render_app(&app, 140, 40);
        assert!(rendered.contains("Message / Observed"));
        assert!(rendered.contains("capture: Partial; instruction authority: none"));
        assert!(rendered.contains("acceptance or task intent not established"));
        assert!(rendered.contains("protected preview (partial): submitted"));
        assert!(!rendered.contains('\u{1b}'));
        app.state
            .detail
            .as_mut()
            .unwrap()
            .evidence_detail
            .as_mut()
            .unwrap()
            .protected_presentation = Some(ProtectedPresentation::Preview {
            text: format!("{} submitted-tail", "prefix ".repeat(30)),
        });
        assert!(render_app(&app, 140, 40).contains("submitted-tail"));
        assert!(render_app(&app, 70, 40).contains("submitted-tail"));
        let mut item = app.state.detail.take().unwrap();
        item.evidence_detail
            .as_mut()
            .unwrap()
            .protected_presentation = Some(ProtectedPresentation::Preview {
            text: "\0".repeat(65_536),
        });
        item.evidence_detail.as_mut().unwrap().protected_length = 1_048_576;
        let response = evertrace_protocol::envelope::ServerEnvelope::Response(
            evertrace_protocol::response::ResponseEnvelope {
                request_id: evertrace_domain::ids::RequestId::new_v7(),
                response: evertrace_protocol::response::Response::HumanGovernance(
                    evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                        diagnostics: None,
                        frontier: 1,
                        status: evertrace_protocol::dto::HumanSnapshotStatus::Ready,
                        degraded_reasons: vec![],
                        items: vec![item],
                        next_cursor: None,
                    },
                ),
            },
        );
        let mut framed = Vec::new();
        evertrace_protocol::frame::write_frame_sync(
            &mut framed,
            &response,
            evertrace_protocol::dto::MAX_FRAME_SIZE,
        )
        .unwrap();
        assert!(framed.len() > 6 * 65_536);
        let mut rejected = Vec::new();
        assert!(matches!(
            evertrace_protocol::frame::write_frame_sync(&mut rejected, &response, 65_536),
            Err(evertrace_protocol::frame::FrameError::Oversize)
        ));
        assert!(rejected.is_empty());
    }

    #[test]
    fn provisional_work_detail_remains_a_protected_plan() {
        let mut app = App::with_language(crate::Language::English);
        app.state.route = crate::Route::Explorer;
        let mut item = snapshot_item("task", "task-test".into());
        assert!(
            !String::from_utf8(evertrace_protocol::frame::canonical_json(&item).unwrap())
                .unwrap()
                .contains("work_detail")
        );
        item.work_detail = Some(evertrace_protocol::dto::HumanWorkDetail {
            canonical_goal: "inspect \u{1b}[31m source".into(),
            identity_confidence: evertrace_domain::work::TaskIdentityConfidence::Provisional,
            source_refs: vec!["source-observation".into()],
            workstream_goal: None,
            phase: None,
            acceptance: None,
        });
        app.state.detail = Some(item);
        app.state.detail_frontier = None;
        let rendered = render_app(&app, 100, 40);
        assert!(
            rendered.contains("Provisional") && rendered.contains("instruction authority: none")
        );
        // The existing narrow Inspector wraps this warning across lines.
        assert!(rendered.contains("not execution") && rendered.contains("authorization"));
        assert!(rendered.contains("source-observation") && !rendered.contains('\u{1b}'));
    }

    pub(super) fn snapshot_item(family: &str, object_ref: String) -> HumanSnapshotItem {
        let (category, object_family) = match family {
            "recovery_bundle" => (HumanItemCategory::RecoveryEvidence, HumanObjectFamily::Work),
            "worktree" => (HumanItemCategory::Repository, HumanObjectFamily::Work),
            _ => (HumanItemCategory::Work, HumanObjectFamily::Work),
        };
        HumanSnapshotItem {
            source_context: None,
            semantic_detail: None,
            proposal_base: None,
            evidence_detail: None,
            work_detail: None,
            item_kind: HumanItemKind::Generic,
            proposal: None,
            proposal_review: None,
            support_detail: None,
            competing_detail: None,
            forget_preview: None,
            repository_purge_preview: None,
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
