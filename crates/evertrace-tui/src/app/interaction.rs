use super::*;
use crate::{
    command::UiCommandSpec,
    state::{DetailView, Focus, NavigationFrame, SystemView},
};
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    layout::Position,
    text::Line,
    widgets::{Block, Borders, Wrap},
};

impl App {
    fn detail_rows(&self) -> Vec<String> {
        views::wrap_content(
            &views::detail_text(&self.state),
            self.visible_layout
                .borrow()
                .inspector
                .width
                .saturating_sub(2),
        )
    }
    fn max_detail_scroll(&self) -> u16 {
        self.detail_rows()
            .len()
            .saturating_sub(
                self.visible_layout
                    .borrow()
                    .inspector
                    .height
                    .saturating_sub(2) as usize,
            )
            .min(u16::MAX as usize) as u16
    }
    pub(super) fn modal_open(&self) -> bool {
        self.state.proposal_edit.is_some()
            || self.state.proposal_confirmation.is_some()
            || self.state.recovery_confirmation.is_some()
            || self.state.repository_purge_confirmation.is_some()
            || self.state.future_operation_shell.is_some()
    }
    pub(super) fn save_navigation(&mut self, result_jump: bool) {
        let s = &self.state;
        let frame = NavigationFrame {
            explorer_selection: s.ui.explorer_selection,
            result_jump,
            page_cursor: s.ui.page_cursor.clone(),
            type_filter: s.ui.type_filter.clone(),
            scope_filter: s.ui.scope_filter.clone(),
            state_filter: s.ui.state_filter.clone(),
            system_view: s.ui.system_view,
            read_at: s.ui.read_at,
            route: s.route,
            human: s.human.clone(),
            detail: s.detail.clone(),
            detail_frontier: s.detail_frontier,
            selection: s.selection,
            scroll: s.detail_scroll,
            offset: s.ui.list_offset,
            filter: s.ui.filter.clone(),
            related: s.related_context.clone(),
            detail_view: s.ui.detail_view,
        };
        if self.state.ui.history.len() == 8 {
            self.state.ui.history.remove(0);
        }
        self.state.ui.history.push(frame);
    }
    fn restore_navigation(&mut self) -> bool {
        let Some(frame) = self.state.ui.history.pop() else {
            return false;
        };
        let s = &mut self.state;
        s.route = frame.route;
        s.human = frame.human;
        s.detail = frame.detail;
        s.detail_frontier = frame.detail_frontier;
        s.selection = frame.selection;
        s.detail_scroll = frame.scroll;
        s.ui.list_offset = frame.offset;
        s.ui.filter = frame.filter;
        s.related_context = frame.related;
        s.ui.related_loaded = s.related_context.is_some();
        s.ui.detail_view = frame.detail_view;
        s.ui.page_cursor = frame.page_cursor;
        s.ui.type_filter = frame.type_filter;
        s.ui.scope_filter = frame.scope_filter;
        s.ui.state_filter = frame.state_filter;
        s.ui.system_view = frame.system_view;
        s.ui.explorer_selection = frame.explorer_selection;
        s.ui.read_at = frame.read_at;
        s.ui.reference_request = None;
        s.detail_message = None;
        s.ui.focus = if s.detail.is_some() {
            Focus::Detail
        } else {
            Focus::List
        };
        true
    }
    pub(super) fn restore_failed_result(&mut self) -> bool {
        if self.state.ui.reference_request.is_none() || !self.restore_navigation() {
            return false;
        }
        self.state.ui.read_generation = self.state.ui.read_generation.wrapping_add(1).max(1);
        self.state.ui.reading = false;
        self.state.detail_message = Some(self.state.language.text(
            "Task result could not be opened; returned to the original task. The result may be missing or unavailable.",
            "无法打开任务结果；已返回原任务。结果可能不存在或暂不可访问。",
        ).into());
        true
    }
    pub(super) fn specs(&self) -> Vec<UiCommandSpec> {
        use UiCommand::*;
        let s = &self.state;
        let mut out = Vec::new();
        let mut add = |command, name, reason: Option<&'static str>| {
            out.push(UiCommandSpec {
                command,
                name: s.language.label(name),
                search_name: name,
                reason: reason.map(|reason| s.language.reason(reason)),
            })
        };
        add(
            Detail,
            "Open detail",
            (!(s.route == crate::Route::System
                && matches!(
                    s.ui.system_view,
                    crate::state::SystemView::Diagnostics | crate::state::SystemView::Configuration
                ))
                && !views::visible_indices(s).contains(&s.selection))
            .then_some("Select a matching item"),
        );
        add(CycleType, "Type (current page)", Option::None);
        add(CycleScope, "Scope (current page)", Option::None);
        add(CycleState, "State (current page)", Option::None);
        if s.detail.is_some() {
            add(
                DetailView(crate::state::DetailView::Content),
                "Content",
                Option::None,
            );
            add(
                DetailView(crate::state::DetailView::Technical),
                "Technical fields",
                Option::None,
            );
            add(
                DetailView(crate::state::DetailView::Sources),
                "Sources",
                related_context(s)
                    .is_none()
                    .then_some("No supported source relation"),
            );
            if matches!(
                s.detail.as_ref().and_then(|i| i.system_detail.as_ref()),
                Some(evertrace_protocol::dto::HumanSystemDetail::Job { .. })
            ) {
                add(OpenResult,"Open task result",(!matches!(s.detail.as_ref().and_then(|i|i.system_detail.as_ref()),Some(evertrace_protocol::dto::HumanSystemDetail::Job {detail}) if detail.terminal_result_ref.is_some())).then_some("No result reference supplied"));
            }
            add(
                OpenRelated,
                "Open sources / dependencies",
                related_context(s)
                    .is_none()
                    .then_some("No readable source relation"),
            );
            add(
                DetailView(crate::state::DetailView::History),
                "Revision history",
                (!s.detail.as_ref().is_some_and(|i| {
                    i.revision_ref.is_some()
                        && matches!(
                            i.object_kind.as_str(),
                            "atom_revision" | "procedure_revision" | "core_membership"
                        )
                }))
                .then_some("Revision history is not provided for this type"),
            );
            if s.route == crate::Route::Explorer {
                add(
                    ToggleExportSelection,
                    "Select / unselect for export",
                    Option::None,
                );
            }
            if current_proposal_review(s).is_some() {
                for (decision, name) in [
                    (
                        evertrace_protocol::dto::ProposalHumanDecision::Accept,
                        "Accept proposal",
                    ),
                    (
                        evertrace_protocol::dto::ProposalHumanDecision::MergeAndAccept,
                        "Merge and accept",
                    ),
                    (
                        evertrace_protocol::dto::ProposalHumanDecision::Defer,
                        "Defer proposal",
                    ),
                    (
                        evertrace_protocol::dto::ProposalHumanDecision::Reject,
                        "Reject proposal",
                    ),
                ] {
                    add(
                        PrepareProposal(decision),
                        name,
                        proposal_action(s, decision)
                            .is_none()
                            .then_some(proposal_action_unavailable_reason(s, decision)),
                    );
                }
                add(
                    OpenProposalEditor,
                    "Edit and accept",
                    current_proposal_review(s)
                        .is_none_or(|r| !proposal_payload_edit_supported(&r.proposal.payload))
                        .then_some("This payload cannot be edited"),
                );
            }
            if s.detail
                .as_ref()
                .is_some_and(|i| i.support_detail.is_some())
            {
                add(
                    OpenProposalEditor,
                    "Submit replacement",
                    proposal_edit_state(s).err(),
                );
                add(
                    OpenSupportDeprecateEditor,
                    "Submit deprecation",
                    support_deprecate_edit_state(s).err(),
                );
            }
            if s.detail
                .as_ref()
                .is_some_and(|i| i.negative_review.is_some())
            {
                for (d, n) in [
                    (
                        evertrace_protocol::dto::NegativeReviewDecision::ResolveAsIneffective,
                        "Resolve as ineffective",
                    ),
                    (
                        evertrace_protocol::dto::NegativeReviewDecision::DismissAttribution,
                        "Dismiss attribution",
                    ),
                    (
                        evertrace_protocol::dto::NegativeReviewDecision::ConfirmHarm,
                        "Confirm harm",
                    ),
                    (
                        evertrace_protocol::dto::NegativeReviewDecision::RequestRevision,
                        "Request revision",
                    ),
                ] {
                    add(
                        PrepareNegativeReview(d),
                        n,
                        negative_review_action(s, d)
                            .is_none()
                            .then_some("Domain conditions are not satisfied"),
                    );
                }
            }
            add(
                PrepareForgetObject,
                "Forget object (preview)",
                forget_object_action(s)
                    .is_none()
                    .then_some("No eligible Forget preview"),
            );
            add(
                PrepareRepositoryPurge,
                "Purge repository (preview)",
                repository_purge_confirmation(s)
                    .is_none()
                    .then_some("No repository purge preview"),
            );
            add(
                PrepareMarkNewAttempt,
                "Mark new attempt",
                mark_new_attempt_action(s)
                    .is_none()
                    .then_some("Not an eligible interrupted attempt"),
            );
            add(
                PrepareCompetingSelected,
                "Choose competing attempt",
                competing_selected_action(s)
                    .is_none()
                    .then_some("No eligible candidate selected"),
            );
            add(
                SelectCompetingPrevious,
                "Previous competing candidate",
                s.detail
                    .as_ref()
                    .and_then(|i| i.competing_detail.as_ref())
                    .is_none_or(|d| d.eligible_attempt_ids.len() < 2)
                    .then_some("No other competing candidate"),
            );
            add(
                SelectCompetingNext,
                "Next competing candidate",
                s.detail
                    .as_ref()
                    .and_then(|i| i.competing_detail.as_ref())
                    .is_none_or(|d| d.eligible_attempt_ids.len() < 2)
                    .then_some("No other competing candidate"),
            );
            for (kind, name) in [
                (
                    evertrace_domain::repository::RecoveryApplicationKind::Patch,
                    "Recover patch",
                ),
                (
                    evertrace_domain::repository::RecoveryApplicationKind::FileRestore,
                    "Recover files",
                ),
                (
                    evertrace_domain::repository::RecoveryApplicationKind::IndexRestore,
                    "Recover index",
                ),
                (
                    evertrace_domain::repository::RecoveryApplicationKind::Mixed,
                    "Recover mixed",
                ),
            ] {
                add(
                    PrepareRecovery(kind),
                    name,
                    selected_recovery_bundle(s)
                        .is_none()
                        .then_some("Select a RecoveryBundle"),
                );
            }
        }
        if s.route == crate::Route::System {
            if let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                items, ..
            }) = &s.human
            {
                for ((index,_),name) in items.iter().enumerate().filter(|(_,i)|matches!(&i.system_detail,Some(evertrace_protocol::dto::HumanSystemDetail::Job{detail}) if detail.terminal_result_ref.is_some())).take(3).zip(["First result on this page","Second result on this page","Third result on this page"]) {add(OpenResultAt(index),name,Option::None);}
            }
            for (v, n) in [
                (crate::state::SystemView::Overview, "Overview"),
                (crate::state::SystemView::Jobs, "Jobs"),
                (
                    crate::state::SystemView::Diagnostics,
                    "Capture and diagnostics",
                ),
                (crate::state::SystemView::Configuration, "Configuration"),
                (crate::state::SystemView::Maintenance, "Maintenance"),
            ] {
                add(SystemView(v), n, Option::None);
            }
            add(OpenConfigEditor, "Edit configuration", Option::None);
            add(
                PrepareCreateBackup,
                "Submit backup job",
                create_backup_action(s)
                    .is_none()
                    .then_some("Read a current snapshot first"),
            );
            add(
                PrepareVerifyBackup,
                "Submit backup verification",
                verify_backup_action(s)
                    .is_none()
                    .then_some("Select a completed backup"),
            );
            add(
                PrepareCollectGarbage,
                "Submit orphan GC",
                create_backup_action(s)
                    .is_none()
                    .then_some("Read a current snapshot first"),
            );
            add(
                ExportSelection,
                "Export selected objects",
                s.export_selections
                    .is_empty()
                    .then_some("Select objects in Explorer first"),
            );
            add(
                OpenFutureOperationShell,
                "Restore (offline instructions)",
                Option::None,
            );
            for (a, n) in [
                (
                    evertrace_protocol::dto::RepositoryAccessAction::Enable,
                    "Enable repository",
                ),
                (
                    evertrace_protocol::dto::RepositoryAccessAction::Disable,
                    "Disable repository",
                ),
                (
                    evertrace_protocol::dto::RepositoryAccessAction::Rescan,
                    "Rescan repository",
                ),
            ] {
                add(
                    PrepareRepositoryAccess(a),
                    n,
                    repository_access_action(s, a)
                        .is_none()
                        .then_some("Select an eligible repository"),
                );
            }
        }
        if s.route == crate::Route::Explorer && s.detail.is_none() {
            use evertrace_protocol::dto::HumanExplorerListSelection::{Capture, Memories};
            for (selection, en, zh) in [
                (Some(Memories), "Memory results", "记忆结果"),
                (Some(Capture), "Capture records", "采集记录"),
                (Option::None, "All records", "全部"),
            ] {
                add(
                    ExplorerSelection(selection),
                    s.language.text(en, zh),
                    Option::None,
                );
            }
        }
        for (c, n) in [
            (Language(crate::Language::Chinese), "中文"),
            (Language(crate::Language::English), "English"),
            (Filter, "Filter / find loaded content"),
            (ClearFilter, "Clear filter / find"),
            (FindPrevious, "Previous match"),
            (FindNext, "Next match"),
            (Zoom, "Zoom / restore current area"),
            (FirstPage, "First page"),
            (Refresh, "Refresh"),
            (CancelModal, "Back"),
            (Navigate(crate::Route::Inbox), "Inbox"),
            (Navigate(crate::Route::Explorer), "Explorer"),
            (Navigate(crate::Route::System), "System"),
            (Commands, "Commands"),
            (Help, "Help"),
            (Quit, "Quit"),
        ] {
            add(c, n, Option::None);
        }
        add(
            NextPage,
            "Next page",
            (!matches!(
                &s.human,
                Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                    next_cursor: Some(_),
                    ..
                })
            ))
            .then_some("End of loaded pages"),
        );
        out
    }
    fn execute_spec(&mut self, command: UiCommand) -> UiCommand {
        if let Some(reason) = self
            .specs()
            .iter()
            .find(|s| s.command == command)
            .and_then(|s| s.reason)
        {
            self.state.detail_message = Some(crate::locale::format!(
                self.state.language,
                "Unavailable: {reason}",
                "暂不可用：{reason}"
            ));
            return UiCommand::None;
        }
        self.dispatch(command)
    }
    fn palette(&self) -> Vec<UiCommandSpec> {
        let q = self.state.ui.query.to_lowercase();
        self.specs()
            .into_iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&q)
                    || s.search_name.to_lowercase().contains(&q)
                    || crate::Language::Chinese.label(s.search_name).contains(&q)
            })
            .collect()
    }
    pub(super) fn apply_query(&mut self) {
        if self.state.ui.input == Some(false) {
            if self.state.detail.is_some() {
                self.state.ui.find = self.state.ui.query.clone();
                self.find_match(true);
            } else {
                self.state.ui.filter = self.state.ui.query.clone();
                self.state.ui.list_offset = 0;
                if let Some(index) = views::visible_indices(&self.state).first() {
                    self.state.selection = *index;
                }
            }
        }
    }
    fn find_match(&mut self, forward: bool) {
        let width = self
            .visible_layout
            .borrow()
            .inspector
            .width
            .saturating_sub(2);
        let matches = views::detail_text(&self.state)
            .lines()
            .scan(0usize, |offset, l| {
                let start = *offset;
                *offset += views::wrap_content(l, width).len();
                Some((start, l))
            })
            .filter_map(|(i, l)| {
                (!self.state.ui.find.is_empty()
                    && l.to_lowercase()
                        .contains(&self.state.ui.find.to_lowercase()))
                .then_some(i as u16)
            })
            .collect::<Vec<_>>();
        let scroll = self.state.detail_scroll;
        let next = if forward {
            matches.iter().find(|i| **i > scroll).or(matches.first())
        } else {
            matches
                .iter()
                .rev()
                .find(|i| **i < scroll)
                .or(matches.last())
        };
        if let Some(i) = next {
            self.state.detail_scroll = *i;
        }
    }
    pub(super) fn ui_dispatch(&mut self, command: UiCommand) -> Option<UiCommand> {
        match command {
            UiCommand::Language(language) => {
                self.state.language = language;
                return Some(UiCommand::None);
            }
            UiCommand::Detail
                if self.state.route == crate::Route::System
                    && self.state.detail.is_none()
                    && self.state.ui.system_view == SystemView::Diagnostics =>
            {
                self.state.ui.diagnostic_detail = true;
                self.state.detail_scroll = 0;
                return Some(UiCommand::None);
            }
            UiCommand::Detail
                if self.state.route == crate::Route::System
                    && self.state.detail.is_none()
                    && self.state.ui.system_view == SystemView::Configuration =>
            {
                return Some(self.dispatch(UiCommand::OpenConfigEditor));
            }
            UiCommand::OpenResult | UiCommand::OpenResultAt(_) => {
                let item = if let UiCommand::OpenResultAt(index) = command {
                    match &self.state.human {
                        Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                            items,
                            ..
                        }) => items.get(index),
                        _ => None,
                    }
                } else {
                    self.state.detail.as_ref()
                };
                let Some(evertrace_protocol::dto::HumanSystemDetail::Job { detail }) =
                    item.and_then(|i| i.system_detail.as_ref())
                else {
                    return Some(UiCommand::None);
                };
                let Some(reference) = detail.terminal_result_ref.clone() else {
                    return Some(UiCommand::None);
                };
                let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                    frontier,
                    ..
                }) = &self.state.human
                else {
                    return Some(UiCommand::None);
                };
                let frontier = *frontier;
                self.save_navigation(true);
                self.state.ui.explorer_selection = None;
                self.state.ui.read_generation =
                    self.state.ui.read_generation.wrapping_add(1).max(1);
                self.state.ui.page_cursor = None;
                self.state.ui.filter.clear();
                self.state.ui.type_filter = None;
                self.state.ui.scope_filter = None;
                self.state.ui.state_filter = None;
                self.state.related_context = None;
                self.state.ui.related_loaded = false;
                self.state.ui.list_offset = 0;
                self.state.selection = 0;
                self.state.human = None;
                self.state.detail_frontier = None;
                self.state.detail_message = None;
                self.state.detail_scroll = 0;
                self.state.ui.reference_request = Some((reference, frontier));
                self.state.route = crate::Route::Explorer;
                self.state.detail = None;
                self.state.ui.reading = true;
                return Some(UiCommand::Detail);
            }
            UiCommand::NextPage => {
                if let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                    next_cursor: Some(after),
                    ..
                }) = &self.state.human
                {
                    self.state.ui.page_cursor = Some(after.clone());
                    self.state.ui.reading = true;
                }
                self.state.detail = None;
                self.state.ui.list_offset = 0;
                return None;
            }
            UiCommand::FirstPage => {
                self.state.ui.page_cursor = None;
                return None;
            }
            UiCommand::CycleType | UiCommand::CycleScope | UiCommand::CycleState => {
                let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                    items, ..
                }) = &self.state.human
                else {
                    return Some(UiCommand::None);
                };
                let values = items
                    .iter()
                    .filter_map(|i| match command {
                        UiCommand::CycleType => Some(i.object_kind.clone()),
                        UiCommand::CycleScope => i.scope_ref.clone(),
                        _ => Some(views::item_state(i)),
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let value = match command {
                    UiCommand::CycleType => &mut self.state.ui.type_filter,
                    UiCommand::CycleScope => &mut self.state.ui.scope_filter,
                    _ => &mut self.state.ui.state_filter,
                };
                *value = value
                    .as_ref()
                    .and_then(|v| values.iter().position(|x| x == v))
                    .map_or_else(|| values.first().cloned(), |i| values.get(i + 1).cloned());
                self.state.ui.list_offset = 0;
                if let Some(i) = views::visible_indices(&self.state).first() {
                    self.state.selection = *i;
                }
            }
            UiCommand::Commands => {
                self.state.ui.input = Some(true);
                self.state.ui.query.clear();
                self.state.ui.query_cursor = 0;
                self.state.ui.palette_selection = 0;
            }
            UiCommand::Help => self.state.ui.help = !self.state.ui.help,
            UiCommand::Filter => {
                self.state.ui.input = Some(false);
                self.state.ui.query = if self.state.detail.is_some() {
                    self.state.ui.find.clone()
                } else {
                    self.state.ui.filter.clone()
                };
                self.state.ui.query_cursor = self.state.ui.query.len();
            }
            UiCommand::ClearFilter => {
                self.state.ui.filter.clear();
                self.state.ui.find.clear();
                self.state.ui.query.clear();
                self.state.ui.type_filter = None;
                self.state.ui.scope_filter = None;
                self.state.ui.state_filter = None;
            }
            UiCommand::ExplorerSelection(selection) => {
                if self.state.route != crate::Route::Explorer {
                    return None;
                }
                self.state.ui.explorer_selection = selection;
                self.state.human = None;
                self.state.detail = None;
                self.state.detail_frontier = None;
                self.state.detail_message = None;
                self.state.related_context = None;
                self.state.ui.related_loaded = false;
                self.state.ui.reference_request = None;
                self.state.ui.page_cursor = None;
                self.state.ui.type_filter = None;
                self.state.ui.scope_filter = None;
                self.state.ui.state_filter = None;
                self.state.ui.filter.clear();
                self.state.selection = 0;
                self.state.ui.list_offset = 0;
                self.state.detail_scroll = 0;
                self.state.ui.focus = Focus::List;
                self.state.ui.read_generation =
                    self.state.ui.read_generation.wrapping_add(1).max(1);
                self.state.ui.reading = true;
                return Some(UiCommand::Refresh);
            }
            UiCommand::FindNext => self.find_match(true),
            UiCommand::FindPrevious => self.find_match(false),
            UiCommand::Zoom => self.state.ui.zoom = !self.state.ui.zoom,
            UiCommand::SystemView(view) => {
                let previous_scope = super::system_selection(&self.state);
                self.state.ui.system_view = view;
                self.state.detail = None;
                self.state.ui.focus = Focus::List;
                self.state.ui.list_offset = 0;
                if previous_scope != super::system_selection(&self.state) {
                    self.state.human = None;
                    self.state.detail_frontier = None;
                    self.state.detail_message = None;
                    self.state.ui.page_cursor = None;
                    self.state.ui.diagnostic_detail = false;
                    self.state.ui.diagnostic_selection = 0;
                    self.state.ui.type_filter = None;
                    self.state.ui.scope_filter = None;
                    self.state.ui.state_filter = None;
                    self.state.selection = 0;
                    self.state.detail_scroll = 0;
                    self.state.ui.read_generation =
                        self.state.ui.read_generation.wrapping_add(1).max(1);
                    self.state.ui.reading = true;
                    return Some(UiCommand::Refresh);
                }
                if let Some(index) = views::visible_indices(&self.state).first() {
                    self.state.selection = *index;
                }
            }
            UiCommand::DetailView(view) => {
                if view == DetailView::Sources {
                    return Some(self.dispatch(UiCommand::OpenRelated));
                }
                if view == DetailView::History && self.state.detail.is_some() {
                    self.save_navigation(false);
                }
                self.state.ui.detail_view = view;
                self.state.detail_scroll = 0;
                if matches!(view, DetailView::Sources | DetailView::History)
                    && self.state.detail.is_some()
                {
                    self.state.ui.related_loaded = false;
                    self.state.ui.page_cursor = None;
                    let relation = if view == DetailView::History {
                        evertrace_protocol::dto::HumanRelationKind::ObjectRevisions
                    } else {
                        evertrace_protocol::dto::HumanRelationKind::ObjectSources
                    };
                    let item = self.state.detail.as_ref()?;
                    let Some(revision) = item.revision_ref.clone() else {
                        return Some(UiCommand::None);
                    };
                    let Some(frontier) = action_frontier(&self.state) else {
                        return Some(UiCommand::None);
                    };
                    self.state.related_context = Some(crate::state::RelatedContext {
                        relation,
                        source_stable_key: item.stable_key.clone(),
                        expected_source_revision_ref: revision,
                        expected_frontier: frontier,
                    });
                    return Some(UiCommand::OpenRelated);
                }
            }
            UiCommand::CancelModal if !self.modal_open() => {
                if self.state.ui.diagnostic_detail {
                    self.state.ui.diagnostic_detail = false;
                    self.state.detail_scroll = 0;
                    return Some(UiCommand::None);
                }
                if self.state.ui.input.take().is_some() {
                    return Some(UiCommand::None);
                }
                if self.state.ui.help {
                    self.state.ui.help = false;
                    return Some(UiCommand::None);
                }
                if (self.state.detail.is_none()
                    || self
                        .state
                        .ui
                        .history
                        .last()
                        .is_some_and(|frame| frame.result_jump))
                    && self.restore_navigation()
                {
                    return Some(UiCommand::None);
                }
                self.state.ui.focus = Focus::List;
                return None;
            }
            UiCommand::SelectNext | UiCommand::SelectPrevious if !self.modal_open() => {
                let down = command == UiCommand::SelectNext;
                if self.state.ui.focus != Focus::Detail {
                    self.state.ui.read_generation =
                        self.state.ui.read_generation.wrapping_add(1).max(1);
                    self.state.ui.reading = false;
                }
                if self.state.route == crate::Route::System
                    && self.state.ui.system_view == SystemView::Diagnostics
                    && !self.state.ui.diagnostic_detail
                {
                    let count = match &self.state.human {
                        Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                            diagnostics: Some(report),
                            ..
                        }) => report.checks.len(),
                        _ => 0,
                    };
                    self.state.ui.diagnostic_selection = if down {
                        (self.state.ui.diagnostic_selection + 1).min(count.saturating_sub(1))
                    } else {
                        self.state.ui.diagnostic_selection.saturating_sub(1)
                    };
                    self.state.detail_scroll =
                        self.state
                            .ui
                            .diagnostic_selection
                            .saturating_sub(5)
                            .min(u16::MAX as usize) as u16;
                    return Some(UiCommand::None);
                }
                if (self.state.ui.focus == Focus::Detail && self.state.detail.is_some())
                    || (self.state.route == crate::Route::System
                        && self.state.ui.system_view == SystemView::Diagnostics)
                {
                    self.state.detail_scroll = if down {
                        self.state.detail_scroll.saturating_add(1)
                    } else {
                        self.state.detail_scroll.saturating_sub(1)
                    };
                } else {
                    let rows = views::visible_indices(&self.state);
                    let at = rows
                        .iter()
                        .position(|i| *i == self.state.selection)
                        .unwrap_or(0);
                    let next = if down {
                        at.saturating_add(1).min(rows.len().saturating_sub(1))
                    } else {
                        at.saturating_sub(1)
                    };
                    if let Some(i) = rows.get(next) {
                        self.state.selection = *i;
                        self.state.detail = None;
                        self.state.detail_message = None;
                    }
                    let height = self
                        .visible_layout
                        .borrow()
                        .list
                        .height
                        .saturating_sub(2)
                        .max(1) as usize;
                    if next < self.state.ui.list_offset {
                        self.state.ui.list_offset = next;
                    }
                    if next >= self.state.ui.list_offset + height {
                        self.state.ui.list_offset = next + 1 - height;
                    }
                }
            }
            _ => return None,
        }
        Some(UiCommand::None)
    }
    pub(super) fn interaction_key(&mut self, key: KeyEvent) -> UiCommand {
        if self.modal_open() {
            return match key.code {
                KeyCode::Esc => self.dispatch(UiCommand::CancelModal),
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                    self.state.ui.confirmation_selected = !self.state.ui.confirmation_selected;
                    UiCommand::None
                }
                KeyCode::Up => {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_sub(1);
                    UiCommand::None
                }
                KeyCode::Down => {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_add(1);
                    UiCommand::None
                }
                KeyCode::Enter => {
                    let c = if self.state.ui.confirmation_selected {
                        UiCommand::Detail
                    } else {
                        UiCommand::CancelModal
                    };
                    self.state.ui.confirmation_selected = false;
                    self.dispatch(c)
                }
                _ => UiCommand::None,
            };
        }
        if let Some(commands) = self.state.ui.input {
            match key.code {
                KeyCode::Esc => {
                    self.state.ui.input = None;
                }
                KeyCode::Enter => {
                    self.state.ui.input = None;
                    if commands {
                        let command = self
                            .palette()
                            .get(self.state.ui.palette_selection)
                            .map(|s| s.command);
                        if let Some(c) = command {
                            return self.execute_spec(c);
                        }
                    }
                }
                KeyCode::Up if commands => {
                    self.state.ui.palette_selection =
                        self.state.ui.palette_selection.saturating_sub(1)
                }
                KeyCode::Down if commands => {
                    self.state.ui.palette_selection = (self.state.ui.palette_selection + 1)
                        .min(self.palette().len().saturating_sub(1))
                }
                KeyCode::Backspace => {
                    let start =
                        previous_char_boundary(&self.state.ui.query, self.state.ui.query_cursor);
                    self.state
                        .ui
                        .query
                        .replace_range(start..self.state.ui.query_cursor, "");
                    self.state.ui.query_cursor = start;
                    self.state.ui.palette_selection = 0;
                    self.apply_query();
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if self.state.ui.query.len() < 512 {
                        self.state.ui.query.insert(self.state.ui.query_cursor, c);
                        self.state.ui.query_cursor += c.len_utf8();
                        self.state.ui.palette_selection = 0;
                        self.apply_query();
                    }
                }
                KeyCode::Left => {
                    self.state.ui.query_cursor =
                        previous_char_boundary(&self.state.ui.query, self.state.ui.query_cursor)
                }
                KeyCode::Right => {
                    self.state.ui.query_cursor =
                        next_char_boundary(&self.state.ui.query, self.state.ui.query_cursor)
                }
                KeyCode::Home => self.state.ui.query_cursor = 0,
                KeyCode::End => self.state.ui.query_cursor = self.state.ui.query.len(),
                _ => {}
            }
            return UiCommand::None;
        }
        if self.state.ui.help {
            if key.code == KeyCode::Down {
                self.state.ui.palette_selection =
                    (self.state.ui.palette_selection + 1).min(self.specs().len().saturating_sub(1));
            }
            if key.code == KeyCode::Up {
                self.state.ui.palette_selection = self.state.ui.palette_selection.saturating_sub(1);
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?')) {
                self.state.ui.help = false;
            }
            return UiCommand::None;
        }
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            let mut focuses = vec![Focus::Tabs, Focus::Tools];
            let l = self.visible_layout.borrow();
            if l.list.width > 0 {
                focuses.push(Focus::List);
            }
            if l.inspector.width > 0 {
                focuses.push(Focus::Detail);
            }
            focuses.push(Focus::Actions);
            let i = focuses
                .iter()
                .position(|f| *f == self.state.ui.focus)
                .unwrap_or(0);
            self.state.ui.focus = focuses[(i + if key.code == KeyCode::BackTab {
                focuses.len() - 1
            } else {
                1
            }) % focuses.len()];
            return UiCommand::None;
        }
        if matches!(key.code, KeyCode::Left | KeyCode::Right) {
            let right = key.code == KeyCode::Right;
            match self.state.ui.focus {
                Focus::Tabs => {
                    let routes = [
                        crate::Route::Inbox,
                        crate::Route::Explorer,
                        crate::Route::System,
                    ];
                    let i = routes
                        .iter()
                        .position(|r| *r == self.state.route)
                        .unwrap_or(0);
                    let command = self.dispatch(UiCommand::Navigate(
                        routes[(i + if right { 1 } else { 2 }) % 3],
                    ));
                    self.state.ui.focus = Focus::Tabs;
                    return command;
                }
                Focus::Tools => {
                    let len = self.tool_commands().len();
                    self.state.ui.tool_selection =
                        (self.state.ui.tool_selection + if right { 1 } else { len - 1 }) % len;
                }
                Focus::Actions => {
                    let len = self.action_commands().len();
                    self.state.ui.action_selection =
                        (self.state.ui.action_selection + if right { 1 } else { len - 1 }) % len;
                }
                _ => {}
            }
            return UiCommand::None;
        }
        if key.code == KeyCode::Enter {
            let c = match self.state.ui.focus {
                Focus::Tools => self
                    .tool_commands()
                    .get(self.state.ui.tool_selection)
                    .copied(),
                Focus::Actions => self
                    .action_commands()
                    .get(self.state.ui.action_selection)
                    .copied(),
                _ => None,
            };
            if let Some(c) = c {
                return self.execute_spec(c);
            }
        }
        if matches!(
            key.code,
            KeyCode::PageDown | KeyCode::PageUp | KeyCode::Home | KeyCode::End
        ) {
            let end = matches!(key.code, KeyCode::PageDown | KeyCode::End);
            if self.state.ui.focus == Focus::Detail {
                let max = self.max_detail_scroll();
                self.state.detail_scroll = match key.code {
                    KeyCode::Home => 0,
                    KeyCode::End => max,
                    _ => {
                        if end {
                            self.state.detail_scroll.saturating_add(10).min(max)
                        } else {
                            self.state.detail_scroll.saturating_sub(10)
                        }
                    }
                };
            } else {
                self.state.ui.list_offset =
                    match key.code {
                        KeyCode::Home => 0,
                        KeyCode::End => views::visible_indices(&self.state).len().saturating_sub(1),
                        _ => {
                            if end {
                                self.state.ui.list_offset.saturating_add(10).min(
                                    views::visible_indices(&self.state).len().saturating_sub(1),
                                )
                            } else {
                                self.state.ui.list_offset.saturating_sub(10)
                            }
                        }
                    };
            }
            return UiCommand::None;
        }
        self.execute_spec(keymap::command(key))
    }
    fn tool_commands(&self) -> Vec<UiCommand> {
        if self.state.ui.diagnostic_detail {
            vec![UiCommand::CancelModal]
        } else if self.state.detail.is_some() {
            vec![
                UiCommand::CancelModal,
                UiCommand::DetailView(DetailView::Content),
                UiCommand::DetailView(DetailView::Sources),
                UiCommand::DetailView(DetailView::History),
                UiCommand::DetailView(DetailView::Technical),
            ]
        } else if self.state.route == crate::Route::System {
            vec![
                UiCommand::SystemView(SystemView::Overview),
                UiCommand::SystemView(SystemView::Jobs),
                UiCommand::SystemView(SystemView::Diagnostics),
                UiCommand::SystemView(SystemView::Configuration),
                UiCommand::SystemView(SystemView::Maintenance),
            ]
        } else if self.state.route == crate::Route::Explorer {
            use evertrace_protocol::dto::HumanExplorerListSelection::{Capture, Memories};
            vec![
                UiCommand::ExplorerSelection(Some(Memories)),
                UiCommand::ExplorerSelection(Some(Capture)),
                UiCommand::ExplorerSelection(None),
                UiCommand::Filter,
            ]
        } else {
            vec![
                UiCommand::CycleType,
                if self.state.route == crate::Route::Explorer {
                    UiCommand::CycleScope
                } else {
                    UiCommand::CycleState
                },
                UiCommand::Filter,
                UiCommand::ClearFilter,
            ]
        }
    }
    fn action_commands(&self) -> Vec<UiCommand> {
        if self.state.detail.is_some() && !self.state.ui.find.is_empty() {
            return vec![
                UiCommand::FindPrevious,
                UiCommand::FindNext,
                UiCommand::ClearFilter,
                UiCommand::CancelModal,
            ];
        }
        if self.state.detail.is_some() {
            vec![
                UiCommand::CancelModal,
                UiCommand::OpenRelated,
                UiCommand::Filter,
                UiCommand::Commands,
            ]
        } else {
            vec![
                UiCommand::Detail,
                UiCommand::Filter,
                UiCommand::NextPage,
                UiCommand::Commands,
            ]
        }
    }
    pub(super) fn mouse(&mut self, event: MouseEvent) -> UiCommand {
        if !matches!(
            event.kind,
            MouseEventKind::Down(MouseButton::Left)
                | MouseEventKind::ScrollDown
                | MouseEventKind::ScrollUp
        ) {
            return UiCommand::None;
        }
        if self.modal_open() {
            if event.kind == MouseEventKind::Down(MouseButton::Left) {
                let command = self
                    .hit_regions
                    .borrow()
                    .iter()
                    .find(|(r, c)| {
                        r.contains(Position::new(event.column, event.row))
                            && matches!(c, UiCommand::CancelModal | UiCommand::Detail)
                    })
                    .map(|(_, c)| *c);
                if let Some(command) = command {
                    return self.dispatch(command);
                }
            }
            return UiCommand::None;
        }
        if self.state.ui.input == Some(true) || self.state.ui.help {
            if event.kind == MouseEventKind::Down(MouseButton::Left) {
                let command = self
                    .hit_regions
                    .borrow()
                    .iter()
                    .find(|(r, _)| r.contains(Position::new(event.column, event.row)))
                    .map(|(_, c)| *c);
                if let Some(command) = command {
                    if command == UiCommand::CancelModal {
                        return self.execute_spec(command);
                    }
                    self.state.ui.input = None;
                    self.state.ui.help = false;
                    return self.execute_spec(command);
                }
            }
            return UiCommand::None;
        }
        if self.state.ui.input.is_some() {
            return UiCommand::None;
        }
        let p = Position::new(event.column, event.row);
        if event.kind == MouseEventKind::Down(MouseButton::Left) {
            let c = self
                .hit_regions
                .borrow()
                .iter()
                .find(|(r, _)| r.contains(p))
                .map(|(_, c)| *c);
            if let Some(c) = c {
                if c == UiCommand::Zoom {
                    self.state.ui.focus = if self.visible_layout.borrow().inspector.contains(p) {
                        Focus::Detail
                    } else {
                        Focus::List
                    };
                }
                return self.execute_spec(c);
            }
        }
        let l = self.visible_layout.borrow().clone();
        if l.list.contains(p)
            && self.state.route == crate::Route::System
            && self.state.ui.system_view == SystemView::Diagnostics
        {
            if event.kind == MouseEventKind::Down(MouseButton::Left)
                && !self.state.ui.diagnostic_detail
            {
                let row = event.row.saturating_sub(l.list.y + 4) as usize
                    + self.state.detail_scroll as usize;
                if let Some(evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
                    diagnostics: Some(report),
                    ..
                }) = &self.state.human
                    && let Some((index, _)) = report
                        .checks
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| {
                            c.name
                                .to_lowercase()
                                .contains(&self.state.ui.filter.to_lowercase())
                        })
                        .nth(row)
                {
                    self.state.ui.diagnostic_selection = index;
                }
            } else if event.kind == MouseEventKind::ScrollDown {
                self.state.detail_scroll = self.state.detail_scroll.saturating_add(3);
            } else if event.kind == MouseEventKind::ScrollUp {
                self.state.detail_scroll = self.state.detail_scroll.saturating_sub(3);
            }
            return UiCommand::None;
        }
        if l.inspector.contains(p) {
            self.state.ui.focus = Focus::Detail;
            match event.kind {
                MouseEventKind::ScrollDown => {
                    self.state.detail_scroll = self
                        .state
                        .detail_scroll
                        .saturating_add(3)
                        .min(self.max_detail_scroll())
                }
                MouseEventKind::ScrollUp => {
                    self.state.detail_scroll = self.state.detail_scroll.saturating_sub(3)
                }
                _ => {}
            }
        } else if l.list.contains(p) {
            if event.kind == MouseEventKind::Down(MouseButton::Left) {
                self.state.ui.read_generation =
                    self.state.ui.read_generation.wrapping_add(1).max(1);
                self.state.ui.reading = false;
                self.state.ui.focus = Focus::List;
                let first_row = l.list.y + 1;
                if event.row < first_row || event.row >= l.list.bottom().saturating_sub(1) {
                    return UiCommand::None;
                }
                let row = usize::from(event.row - first_row) + self.state.ui.list_offset;
                if let Some(i) = views::visible_indices(&self.state).get(row) {
                    self.state.selection = *i;
                    self.state.detail = None;
                    self.state.detail_message = None;
                }
            }
            match event.kind {
                MouseEventKind::ScrollDown => {
                    self.state.ui.list_offset = (self.state.ui.list_offset + 3)
                        .min(views::visible_indices(&self.state).len().saturating_sub(1))
                }
                MouseEventKind::ScrollUp => {
                    self.state.ui.list_offset = self.state.ui.list_offset.saturating_sub(3)
                }
                _ => {}
            }
        }
        UiCommand::None
    }
    fn buttons(
        &self,
        frame: &mut Frame,
        area: Rect,
        commands: &[UiCommand],
        selected: Option<usize>,
    ) {
        let specs = self.specs();
        let mut x = area.x;
        // Keep the keyboard-focused action visible even when preceding buttons
        // consume the entire row on a compact terminal.
        let start = if matches!(commands.first(), Some(UiCommand::Navigate(_))) {
            0
        } else {
            selected.unwrap_or(0)
        };
        for (i, c) in commands.iter().enumerate().skip(start) {
            let label = match c {
                UiCommand::OpenResultAt(index) => {
                    crate::locale::format!(self.state.language, "Result {}", "结果 {}", index + 1)
                }
                UiCommand::CycleType => crate::locale::format!(
                    self.state.language,
                    "Type: {}",
                    "类型：{}",
                    self.state
                        .ui
                        .type_filter
                        .as_deref()
                        .map(|value| views::kind_label(value, self.state.language))
                        .unwrap_or(self.state.language.text("all", "全部"))
                ),
                UiCommand::CycleScope => crate::locale::format!(
                    self.state.language,
                    "Scope: {}",
                    "范围：{}",
                    self.state
                        .ui
                        .scope_filter
                        .as_deref()
                        .unwrap_or(self.state.language.text("all", "全部"))
                ),
                UiCommand::CycleState => crate::locale::format!(
                    self.state.language,
                    "State: {}",
                    "状态：{}",
                    self.state
                        .ui
                        .state_filter
                        .as_deref()
                        .map(|value| views::status_label(value, self.state.language))
                        .unwrap_or(self.state.language.text("all", "全部"))
                ),
                UiCommand::DetailView(v) => self
                    .state
                    .language
                    .label(match v {
                        DetailView::Content => "Content",
                        DetailView::Sources => "Sources",
                        DetailView::History => "History",
                        DetailView::Technical => "Technical",
                    })
                    .into(),
                UiCommand::SystemView(v) => self
                    .state
                    .language
                    .label(match v {
                        SystemView::Overview => "Overview",
                        SystemView::Jobs => "Jobs",
                        SystemView::Diagnostics => "Diagnostics",
                        SystemView::Configuration => "Configuration",
                        SystemView::Maintenance => "Maintenance",
                    })
                    .into(),
                _ => specs
                    .iter()
                    .find(|s| s.command == *c)
                    .map_or_else(|| format!("{c:?}"), |s| s.name.into()),
            };
            let text = format!("[{}{}] ", if selected == Some(i) { ">" } else { "" }, label);
            let width = Line::from(text.clone()).width() as u16;
            if x + width > area.right() {
                break;
            }
            let r = Rect::new(x, area.y, width, area.height);
            let disabled = specs
                .iter()
                .find(|s| s.command == *c)
                .is_some_and(|s| s.reason.is_some());
            frame.render_widget(
                Paragraph::new(text).style(Style::default().bg(crate::theme::EVER_OS.surface).fg(
                    if disabled {
                        crate::theme::EVER_OS.muted
                    } else if selected == Some(i) {
                        crate::theme::EVER_OS.cyan
                    } else {
                        crate::theme::EVER_OS.ink
                    },
                )),
                r,
            );
            self.hit_regions.borrow_mut().push((r, *c));
            x += width;
        }
    }
    pub(super) fn render_shell(&self, frame: &mut Frame) {
        self.hit_regions.borrow_mut().clear();
        let s = &self.state;
        let palette = &crate::theme::EVER_OS;
        frame.render_widget(
            Block::default().style(Style::default().bg(palette.background).fg(palette.ink)),
            frame.area(),
        );
        let shell = layout::responsive(
            frame.area(),
            s.detail.is_some(),
            s.ui.zoom,
            s.ui.focus == Focus::Detail,
        );
        *self.visible_layout.borrow_mut() = shell.clone();
        frame.render_widget(Paragraph::new("EverTrace"), shell.header);
        self.buttons(
            frame,
            Rect::new(
                shell.header.x + shell.header.width.min(10),
                shell.header.y,
                shell.header.width.saturating_sub(10),
                shell.header.height,
            ),
            &[
                UiCommand::Navigate(crate::Route::Inbox),
                UiCommand::Navigate(crate::Route::Explorer),
                UiCommand::Navigate(crate::Route::System),
                UiCommand::Commands,
                UiCommand::Help,
            ],
            Some(match s.route {
                crate::Route::Inbox => 0,
                crate::Route::Explorer => 1,
                crate::Route::System => 2,
            }),
        );
        let notice = if s.ui.unknown_write {
            self.state.language.label("Request sent; result unconfirmed. Inspect jobs/results before submitting again").into()
        } else if let Some(message) = &s.detail_message {
            message.clone()
        } else {
            crate::locale::format!(
                self.state.language,
                "{} / {} — loaded page only",
                "{} / {} — 仅当前加载页",
                s.language.label(match s.route {
                    crate::Route::Inbox => "Inbox",
                    crate::Route::Explorer => "Explorer",
                    crate::Route::System => "System",
                }),
                if s.route == crate::Route::System {
                    s.language
                        .label(match s.ui.system_view {
                            SystemView::Overview => "Overview",
                            SystemView::Jobs => "Jobs",
                            SystemView::Diagnostics => "Capture and diagnostics",
                            SystemView::Configuration => "Configuration",
                            SystemView::Maintenance => "Maintenance",
                        })
                        .to_string()
                } else {
                    s.language
                        .label(match s.ui.detail_view {
                            DetailView::Content => "Content",
                            DetailView::Sources => "Sources",
                            DetailView::History => "Revision history",
                            DetailView::Technical => "Technical fields",
                        })
                        .to_string()
                }
            )
        };
        frame.render_widget(
            Paragraph::new(notice).style(Style::default().fg(if s.ui.unknown_write {
                palette.amber
            } else if s.detail_message.is_some() {
                palette.red
            } else {
                palette.muted
            })),
            shell.nav,
        );
        if let Some(selection) = s.recovery_selection {
            frame.render_widget(
                Paragraph::new(crate::locale::format!(
                    self.state.language,
                    "Bundle {} {:?}; select target Worktree; Enter continues",
                    "恢复包 {} {:?}；请选择目标工作树；Enter 继续",
                    selection.recovery_bundle_id,
                    selection.application_kind
                )),
                shell.nav,
            );
        }
        if !s.ui.unknown_write
            && s.detail_message.is_none()
            && let Some(result) = &s.last_action
        {
            use evertrace_protocol::dto::HumanActionStatus;
            let label = match result.status {
                HumanActionStatus::Applied => {
                    if s.ui.action_submits_job {
                        self.state
                            .language
                            .label("Task submitted; not yet completed")
                    } else {
                        self.state.language.label("Action applied")
                    }
                }
                HumanActionStatus::NoDelta => {
                    s.language.text("No change needed", "当前状态无需变更")
                }
                HumanActionStatus::Conflict => s.language.text(
                    "Object changed; action not applied. Reread before confirming",
                    "对象已变化，操作未应用；请重新读取后再确认",
                ),
                HumanActionStatus::Unavailable => {
                    s.language.text("Action unavailable", "操作不可用")
                }
            };
            frame.render_widget(
                Paragraph::new(format!(
                    "{label}: {}",
                    result.reason.as_deref().unwrap_or("")
                )),
                shell.nav,
            );
        }
        if s.route == crate::Route::Explorer
            && !s.ui.unknown_write
            && s.detail_message.is_none()
            && let Some(result) = &s.recovery_result
        {
            frame.render_widget(
                Paragraph::new(crate::locale::format!(
                    self.state.language,
                    "Recovery: {}{}",
                    "恢复: {}{}",
                    result
                        .application_status
                        .map_or_else(|| "unavailable".into(), |status| format!("{status:?}")),
                    result
                        .unsupported_reason
                        .map_or(String::new(), |reason| format!(" — {reason:?}"))
                )),
                shell.nav,
            );
        }
        self.buttons(
            frame,
            shell.tools,
            &self.tool_commands(),
            (s.ui.focus == Focus::Tools).then_some(s.ui.tool_selection),
        );
        if frame.area().width < 60 || frame.area().height < 18 {
            frame.render_widget(Paragraph::new(self.state.language.label("Terminal too small; enlarge the window. Content and edits are retained. Esc back; : commands; ? help")).wrap(Wrap{trim:false}),if shell.list.width>0{shell.list}else{shell.inspector});
        } else {
            if shell.list.width > 0 {
                views::render(frame, shell.list, s);
            }
            if shell.inspector.width > 0 {
                frame.render_widget(
                    Paragraph::new(self.detail_rows().join("\n"))
                        .scroll((s.detail_scroll, 0))
                        .block(
                            Block::default()
                                .title(if s.ui.focus == Focus::Detail {
                                    self.state.language.label("Detail [focused]")
                                } else {
                                    self.state.language.label("Detail")
                                })
                                .borders(Borders::ALL),
                        ),
                    shell.inspector,
                );
            }
        }
        if shell.list.width > 0 && s.route == crate::Route::System {
            let inset = match s.ui.system_view {
                SystemView::Overview => 5,
                SystemView::Maintenance => 7,
                _ => 0,
            };
            let mut l = self.visible_layout.borrow_mut();
            let inset = inset.min(l.list.height);
            l.list.y += inset;
            l.list.height -= inset;
        }
        if s.route == crate::Route::System
            && s.ui.system_view == SystemView::Overview
            && shell.list.height >= 5
        {
            let area = Rect::new(shell.list.x, shell.list.y + 4, shell.list.width, 1);
            let results = self
                .specs()
                .into_iter()
                .filter_map(|spec| {
                    matches!(spec.command, UiCommand::OpenResultAt(_)).then_some(spec.command)
                })
                .collect::<Vec<_>>();
            frame.render_widget(
                Paragraph::new(if results.is_empty() {
                    self.state
                        .language
                        .label("This page: no task result references")
                } else {
                    self.state.language.label("This page results:")
                }),
                area,
            );
            if area.width > 19 {
                self.buttons(
                    frame,
                    Rect::new(area.x + 19, area.y, area.width - 19, 1),
                    &results,
                    None,
                );
            }
        }
        self.buttons(
            frame,
            shell.actions,
            &self.action_commands(),
            (s.ui.focus == Focus::Actions).then_some(s.ui.action_selection),
        );
        for area in [shell.list, shell.inspector] {
            if area.width > 8 && area.height > 0 {
                let rect = Rect::new(area.right() - 5, area.y, 5, 1);
                frame.render_widget(Paragraph::new("[+/-]"), rect);
                self.hit_regions.borrow_mut().push((rect, UiCommand::Zoom));
            }
        }
        let time =
            s.ui.read_at
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or_else(
                    || self.state.language.label("not yet read").into(),
                    |d| {
                        format!(
                            "{:02}:{:02}:{:02} UTC",
                            d.as_secs() / 3600 % 24,
                            d.as_secs() / 60 % 60,
                            d.as_secs() % 60
                        )
                    },
                );
        let loaded = snapshot_item_count(s);
        let matched = views::visible_indices(s).len();
        let page = if s.human.is_some() {
            crate::locale::format!(
                self.state.language,
                "{matched}/{loaded} this page",
                "本页 {matched}/{loaded} 项"
            )
        } else {
            self.state.language.label("page not loaded").into()
        };
        frame.render_widget(
            Paragraph::new(crate::locale::format!(
                self.state.language,
                "{} | Read: {time} | {page}{}",
                "{} | 读取：{time} | {page}{}",
                match s.shell.connection {
                    ConnectionState::Connected => s.language.text("Connected", "已连接"),
                    ConnectionState::Connecting => s.language.text("Connecting", "连接中"),
                    ConnectionState::Disconnected => s.language.text("Disconnected", "已断开"),
                    ConnectionState::ServerStopping =>
                        s.language.text("ServerStopping", "服务正在停止"),
                },
                if s.ui.reading || s.shell.pending > 0 {
                    self.state.language.label(" | refreshing")
                } else {
                    ""
                }
            ))
            .style(Style::default().fg(
                if s.shell.connection == ConnectionState::Connected {
                    palette.green
                } else {
                    palette.amber
                },
            )),
            shell.status,
        );
        frame.render_widget(
            Paragraph::new(if s.ui.focus == Focus::Detail {
                self.state
                    .language
                    .label("↑↓ scroll  Esc back  / find  : commands")
            } else if shell.compact {
                self.state
                    .language
                    .label("↑↓ select  Enter detail  Tab focus  : commands")
            } else {
                self.state
                    .language
                    .label("↑↓ select  Enter detail  Tab/Shift+Tab focus  : commands")
            }),
            shell.hints,
        );
        if s.ui.input == Some(false) || (s.detail.is_some() && !s.ui.find.is_empty()) {
            let label = if s.detail.is_some() {
                self.state.language.label("Find in loaded body")
            } else {
                self.state.language.label("Filter current page")
            };
            let matches = if s.detail.is_some() {
                views::detail_text(s)
                    .lines()
                    .filter(|l| {
                        !s.ui.find.is_empty()
                            && l.to_lowercase().contains(&s.ui.find.to_lowercase())
                    })
                    .count()
            } else {
                matched
            };
            frame.render_widget(
                Paragraph::new(crate::locale::format!(
                    self.state.language,
                    "{label}: {} | {matches} matching lines | Esc closes",
                    "{label}：{} | 匹配 {matches} 行 | Esc 关闭",
                    if s.detail.is_some() {
                        &s.ui.find
                    } else {
                        &s.ui.query
                    }
                )),
                shell.tools,
            );
        }
        if s.ui.input == Some(true) || s.ui.help {
            let area = centered(
                frame.area(),
                76,
                frame.area().height.saturating_sub(2).min(22),
            );
            let entries = if s.ui.help {
                self.specs()
            } else {
                self.palette()
            };
            let visible = area.height.saturating_sub(5) as usize;
            let start =
                s.ui.palette_selection
                    .saturating_sub(visible.saturating_sub(1));
            let body = crate::locale::format!(
                self.state.language,
                "{}\n{}\n↑↓ choose · Enter execute · Esc cancel",
                "{}\n{}\n↑↓ 选择 · Enter 执行 · Esc 取消",
                if s.ui.help {
                    self.state
                        .language
                        .label("Help: Tab/Shift+Tab focus; arrows navigate")
                        .into()
                } else {
                    crate::locale::format!(
                        self.state.language,
                        "Commands: {}",
                        "命令：{}",
                        s.ui.query
                    )
                },
                if entries.is_empty() {
                    s.language
                        .text("No matching commands", "没有匹配命令")
                        .into()
                } else {
                    entries
                        .iter()
                        .enumerate()
                        .skip(start)
                        .take(visible)
                        .map(|(i, e)| {
                            format!(
                                "{} {}{}",
                                if i == s.ui.palette_selection {
                                    ">"
                                } else {
                                    " "
                                },
                                e.name,
                                e.reason.map_or(String::new(), |r| format!(" — {r}"))
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            );
            let (clear, modal) = components::modal(body);
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
            // Only the overlay owns hit regions while it is open. Rows match the
            // actual bordered paragraph's header and scrolled command slice.
            self.hit_regions.borrow_mut().clear();
            for (row, entry) in entries.iter().skip(start).take(visible).enumerate() {
                self.hit_regions.borrow_mut().push((
                    Rect::new(
                        area.x + 1,
                        area.y + 2 + row as u16,
                        area.width.saturating_sub(2),
                        1,
                    ),
                    entry.command,
                ));
            }
            let close = Rect::new(
                area.x + 1,
                area.bottom().saturating_sub(2),
                area.width.saturating_sub(2),
                1,
            );
            frame.render_widget(
                Paragraph::new(self.state.language.label("[Back / close] Esc")),
                close,
            );
            self.hit_regions
                .borrow_mut()
                .push((close, UiCommand::CancelModal));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_protocol::dto::{HumanGovernanceResponse, HumanSnapshotStatus, HumanSurface};
    #[test]
    fn system_scope_switch_restarts_pagination_and_rejects_previous_response() {
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::System));
        let jobs = Some(evertrace_protocol::dto::HumanSystemListSelection::Jobs);
        assert_eq!(crate::app::system_selection(&app.state), jobs);
        app.state.ui.page_cursor = Some("runtime:job:previous".into());
        let generation = app.state.ui.read_generation;
        app.dispatch(UiCommand::SystemView(SystemView::Jobs));
        assert_eq!(app.state.ui.read_generation, generation);
        assert!(app.state.ui.page_cursor.is_some());
        assert_eq!(
            app.dispatch(UiCommand::SystemView(SystemView::Diagnostics)),
            UiCommand::Refresh
        );
        assert_eq!(crate::app::system_selection(&app.state), None);
        assert!(app.state.ui.page_cursor.is_none());
        assert_ne!(app.state.ui.read_generation, generation);
        app.handle(AppEvent::HumanRead {
            surface: HumanSurface::System,
            locator: HumanReadLocator::View {
                generation,
                request: Box::new(HumanReadLocator::List),
            },
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 99,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![],
                next_cursor: Some("old".into()),
            },
        });
        assert!(app.state.human.is_none());
        assert_eq!(
            app.dispatch(UiCommand::SystemView(SystemView::Overview)),
            UiCommand::Refresh
        );
        for command in [UiCommand::Refresh, UiCommand::FirstPage] {
            let request = crate::app::human_request(&app.state, command).unwrap();
            assert!(matches!(
                request,
                evertrace_protocol::dto::HumanGovernanceRequest::Read {
                    request: evertrace_protocol::dto::HumanReadRequest::List {
                        system_selection: Some(_),
                        after: None,
                        ..
                    }
                }
            ));
        }
        app.handle(AppEvent::Disconnected);
        assert_eq!(crate::app::system_selection(&app.state), jobs);
        let command = app.handle(AppEvent::Health(
            evertrace_protocol::response::HealthResponse {
                protocol_version: evertrace_protocol::dto::PROTOCOL_VERSION,
                mode: evertrace_protocol::dto::HealthMode::Normal,
                config_version: 1,
                effective_config_hash: "0".repeat(64),
                algorithm_revision: 1,
                host_canary: None,
            },
        ));
        assert!(matches!(
            crate::app::human_request(&app.state, command),
            Some(evertrace_protocol::dto::HumanGovernanceRequest::Read {
                request: evertrace_protocol::dto::HumanReadRequest::List {
                    system_selection: Some(_),
                    ..
                }
            })
        ));
    }
    fn populated() -> App {
        let mut app = App::with_language(crate::Language::English);
        app.dispatch(UiCommand::Navigate(crate::Route::Explorer));
        app.state.human = Some(HumanGovernanceResponse::Snapshot {
            diagnostics: None,
            frontier: 4,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: vec![],
            items: vec![
                crate::app::tests::snapshot_item("task", "task:first".into()),
                crate::app::tests::snapshot_item("task", "task:second".into()),
            ],
            next_cursor: Some("next".into()),
        });
        app
    }

    #[test]
    fn explorer_category_switch_clears_cursor_and_navigation_restores_category() {
        use evertrace_protocol::dto::HumanExplorerListSelection::{Capture, Memories};
        let mut app = populated();
        app.state.ui.page_cursor = Some("old-page".into());
        app.state.ui.type_filter = Some("host_occurrence".into());
        assert_eq!(
            app.dispatch(UiCommand::ExplorerSelection(Some(Memories))),
            UiCommand::Refresh
        );
        assert_eq!(app.state.ui.explorer_selection, Some(Memories));
        assert!(app.state.ui.page_cursor.is_none());
        assert!(app.state.ui.type_filter.is_none());
        assert!(app.state.human.is_none());
        assert!(matches!(
            super::super::human_request(&app.state, UiCommand::Refresh),
            Some(evertrace_protocol::dto::HumanGovernanceRequest::Read {
                request: evertrace_protocol::dto::HumanReadRequest::List {
                    explorer_selection: Some(Memories),
                    after: None,
                    ..
                }
            })
        ));
        app.save_navigation(false);
        app.dispatch(UiCommand::ExplorerSelection(Some(Capture)));
        assert!(app.restore_navigation());
        assert_eq!(app.state.ui.explorer_selection, Some(Memories));
        for language in [crate::Language::English, crate::Language::Chinese] {
            app.state.language = language;
            app.state.ui.reading = false;
            app.state.human = Some(HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 4,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![],
                next_cursor: None,
            });
            let rendered = draw(&app, 120, 30);
            // TestBackend retains a padding cell after each wide character.
            assert!(
                rendered.split_whitespace().collect::<String>().contains(
                    &language
                        .text(
                            "No generated summaries or memory results yet",
                            "尚无生成的摘要／记忆结果"
                        )
                        .replace(' ', "")
                ),
                "{language:?}\n{rendered}"
            );
        }
    }
    fn draw(app: &App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect()
    }
    #[test]
    fn language_search_and_new_detail_frontier_preserve_page_and_navigation() {
        let mut app = populated();
        let mut item = selected_item(&app.state).unwrap().clone();
        item.object_kind = "core_membership".into();
        let revision = evertrace_domain::revision::RevisionId::new_v7();
        item.revision_ref = Some(revision.to_string());
        if let Some(HumanGovernanceResponse::Snapshot { items, .. }) = &mut app.state.human {
            items[0] = item.clone();
        }
        item.semantic_detail = Some(evertrace_protocol::dto::HumanSemanticDetail {
            object_ref: item.object_ref.clone(),
            revision_ref: item.revision_ref.clone(),
            state: evertrace_protocol::dto::HumanContentState::Ready,
            preview: None,
            original_bytes: 0,
            content: Some(
                evertrace_protocol::dto::HumanSemanticContent::CoreMembership(Box::new(
                    evertrace_domain::semantic::CoreMembership {
                        core_membership_id: evertrace_domain::ids::CoreMembershipId::new_v7(),
                        membership_revision_id: revision,
                        atom_revision_id: revision,
                        scope_identity: evertrace_domain::semantic::CoreScopeIdentity::Global,
                        support_contract_ref: revision,
                        authorization_revision_refs: vec![revision],
                        supersedes_membership_revision_id: None,
                        created_by_acceptance_ref: revision,
                        active: true,
                    },
                )),
            ),
        });
        app.handle(AppEvent::HumanRead {
            surface: HumanSurface::Explorer,
            locator: HumanReadLocator::Detail {
                expected_frontier: 4,
                stable_key: item.stable_key.clone(),
                expected_revision_ref: item.revision_ref.clone(),
            },
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 9,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![item.clone()],
                next_cursor: None,
            },
        });
        assert_eq!(action_frontier(&app.state), Some(9));
        assert!(matches!(
            &app.state.human,
            Some(HumanGovernanceResponse::Snapshot {
                frontier: 4,
                next_cursor: Some(_),
                ..
            })
        ));
        for language in [crate::Language::English, crate::Language::Chinese] {
            app.dispatch(UiCommand::Language(language));
            assert!(views::detail_text(&app.state).contains(&revision.to_string()));
            for query in ["Revision history", "修订历史"] {
                app.state.ui.query = query.into();
                assert!(
                    app.palette()
                        .iter()
                        .any(|s| s.command == UiCommand::DetailView(DetailView::History))
                );
            }
            draw(&app, 80, 24);
            assert!(!app.state.write_queued);
        }
        app.state.ui.query.clear();
        app.dispatch(UiCommand::DetailView(DetailView::History));
        assert_eq!(
            app.state
                .related_context
                .as_ref()
                .unwrap()
                .expected_frontier,
            9
        );
        app.handle(AppEvent::HumanRead {
            surface: HumanSurface::Explorer,
            locator: HumanReadLocator::Related {
                relation: evertrace_protocol::dto::HumanRelationKind::ObjectRevisions,
                source_stable_key: item.stable_key.clone(),
                expected_source_revision_ref: revision.to_string(),
                expected_frontier: 9,
            },
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 12,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![item.clone()],
                next_cursor: Some("history-next".into()),
            },
        });
        assert_eq!(
            app.state
                .related_context
                .as_ref()
                .unwrap()
                .expected_frontier,
            12
        );
        app.dispatch(UiCommand::CancelModal);
        assert_eq!(
            app.state.detail.as_ref().unwrap().stable_key,
            item.stable_key
        );
        assert_eq!(app.state.detail_frontier, Some(9));
        assert!(app.state.related_context.is_none());
        assert!(matches!(
            &app.state.human,
            Some(HumanGovernanceResponse::Snapshot { frontier: 4, .. })
        ));
    }
    #[test]
    fn palette_mouse_tabs_and_empty_jobs_use_visible_context() {
        let mut app = populated();
        app.state.ui.focus = Focus::Tabs;
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Right,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.state.route, crate::Route::System);
        assert_eq!(app.state.ui.focus, Focus::Tabs);
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Right,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.state.route, crate::Route::Inbox);
        app = populated();
        app.state.route = crate::Route::System;
        assert!(draw(&app, 80, 24).contains("No tasks on this page"));
        assert!(draw(&app, 80, 24).contains("More pages are available"));
        assert!(
            app.specs()
                .iter()
                .any(|spec| spec.command == UiCommand::NextPage && spec.reason.is_none())
        );
        let next = app
            .hit_regions
            .borrow()
            .iter()
            .find(|(_, c)| *c == UiCommand::NextPage)
            .unwrap()
            .0;
        assert_eq!(
            app.mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: next.x,
                row: next.y,
                modifiers: KeyModifiers::NONE,
            }),
            UiCommand::NextPage
        );
        assert_eq!(app.state.ui.page_cursor.as_deref(), Some("next"));
        app = populated();
        app.state.route = crate::Route::System;
        app.state.ui.filter = "missing".into();
        assert!(draw(&app, 80, 24).contains("No matches on this page (0 loaded)"));
        app.dispatch(UiCommand::Commands);
        app.state.ui.query = "Explorer".into();
        draw(&app, 80, 24);
        let region = app
            .hit_regions
            .borrow()
            .iter()
            .find(|(_, c)| *c == UiCommand::Navigate(crate::Route::Explorer))
            .unwrap()
            .0;
        app.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.state.ui.input, Some(true));
        app.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: region.x,
            row: region.y,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.state.route, crate::Route::Explorer);
        assert_eq!(app.state.ui.input, None);
        app.dispatch(UiCommand::Commands);
        let disabled = app
            .specs()
            .into_iter()
            .find(|spec| spec.reason.is_some())
            .unwrap();
        app.state.ui.query = disabled.name.into();
        draw(&app, 80, 24);
        let region = app
            .hit_regions
            .borrow()
            .iter()
            .find(|(_, c)| *c == disabled.command)
            .unwrap()
            .0;
        app.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: region.x,
            row: region.y,
            modifiers: KeyModifiers::NONE,
        });
        assert!(
            app.state
                .detail_message
                .as_ref()
                .unwrap()
                .contains("Unavailable:")
        );
        app.dispatch(UiCommand::Commands);
        draw(&app, 80, 24);
        let region = app
            .hit_regions
            .borrow()
            .iter()
            .find(|(_, c)| *c == UiCommand::CancelModal)
            .unwrap()
            .0;
        app.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: region.x,
            row: region.y,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.state.ui.input, None);
        assert_eq!(app.state.route, crate::Route::Explorer);
        app.state.ui.diagnostic_detail = true;
        draw(&app, 80, 24);
        assert!(
            app.hit_regions
                .borrow()
                .iter()
                .any(|(_, c)| *c == UiCommand::CancelModal)
        );
    }
    #[test]
    fn responsive_mouse_filter_and_input_share_selection_without_quitting() {
        assert_eq!(
            App::with_language(crate::Language::English).state.route,
            crate::Route::System
        );
        let mut app = populated();
        draw(&app, 80, 24);
        let list = app.visible_layout.borrow().list;
        app.handle(AppEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: list.x + 2,
            row: list.y + 2,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(app.state.selection, 1);
        app.handle(AppEvent::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: list.x + 2,
            row: list.y + 2,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(app.state.selection, 1);
        app.dispatch(UiCommand::Filter);
        app.handle(AppEvent::Paste("second".into()));
        assert_eq!(views::visible_indices(&app.state), vec![1]);
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
        )));
        assert!(!app.state.quit);
        assert!(views::visible_indices(&app.state).is_empty());
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        )));
        app.dispatch(UiCommand::ClearFilter);
        app.state.detail = selected_item(&app.state).cloned();
        app.state.ui.focus = Focus::Detail;
        draw(&app, 120, 36);
        assert!(app.visible_layout.borrow().list.width > 0);
        assert!(app.visible_layout.borrow().inspector.width > 0);
        draw(&app, 80, 24);
        assert_eq!(app.visible_layout.borrow().list.width, 0);
        assert_eq!(app.visible_layout.borrow().inspector.width, 80);
        assert!(draw(&app, 50, 16).contains("Terminal too small"));
        for kind in [
            crossterm::event::KeyEventKind::Repeat,
            crossterm::event::KeyEventKind::Release,
        ] {
            app.handle(AppEvent::Key(KeyEvent {
                kind,
                ..KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)
            }));
            assert!(!app.state.quit);
        }
        app.handle(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
        )));
        assert!(app.state.quit);
    }
    #[test]
    fn navigation_preserves_refs_filters_and_scroll_and_rejects_old_page() {
        let mut app = populated();
        app.state.selection = 1;
        app.state.ui.filter = "second".into();
        app.state.detail = selected_item(&app.state).cloned();
        app.state.detail_scroll = 6;
        app.state.ui.page_cursor = Some("original".into());
        app.save_navigation(false);
        app.state.detail = None;
        app.state.ui.filter.clear();
        app.state.selection = 0;
        app.state.ui.page_cursor = Some("new".into());
        let before = app.state.human.clone();
        app.handle(AppEvent::HumanRead {
            surface: HumanSurface::Explorer,
            locator: HumanReadLocator::Page {
                after: "old".into(),
            },
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 99,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![],
                next_cursor: None,
            },
        });
        assert_eq!(app.state.human, before);
        app.dispatch(UiCommand::CancelModal);
        assert_eq!(app.state.selection, 1);
        assert_eq!(app.state.detail_scroll, 6);
        assert_eq!(app.state.ui.filter, "second");
        assert_eq!(app.state.ui.page_cursor.as_deref(), Some("original"));
    }
    #[test]
    fn modal_blocks_mouse_and_repeat_and_unknown_write_survives_navigation() {
        let mut app = populated();
        app.state.future_operation_shell = Some(crate::state::FutureOperationShell::Maintenance);
        draw(&app, 80, 24);
        app.handle(AppEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(app.state.route, crate::Route::Explorer);
        app.handle(AppEvent::Key(KeyEvent {
            code: KeyCode::Enter,
            modifiers: KeyModifiers::NONE,
            kind: crossterm::event::KeyEventKind::Repeat,
            state: crossterm::event::KeyEventState::NONE,
        }));
        assert!(app.state.future_operation_shell.is_some());
        app.dispatch(UiCommand::CancelModal);
        app.state.write_queued = true;
        app.handle(AppEvent::Disconnected);
        app.dispatch(UiCommand::Navigate(crate::Route::Inbox));
        assert!(app.state.ui.unknown_write);
        assert!(draw(&app, 120, 36).contains("result unconfirmed"));
    }
    #[test]
    fn response_from_previous_visit_cannot_replace_same_route_snapshot() {
        let mut app = populated();
        let previous_generation = app.state.ui.read_generation;
        let snapshot = app.state.human.clone();
        app.dispatch(UiCommand::Navigate(crate::Route::System));
        app.dispatch(UiCommand::Navigate(crate::Route::Explorer));
        app.state.human = snapshot.clone();
        app.handle(AppEvent::HumanRead {
            surface: HumanSurface::Explorer,
            locator: HumanReadLocator::View {
                generation: previous_generation,
                request: Box::new(HumanReadLocator::List),
            },
            response: HumanGovernanceResponse::Snapshot {
                diagnostics: None,
                frontier: 99,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: vec![],
                items: vec![],
                next_cursor: None,
            },
        });
        assert_eq!(app.state.human, snapshot);
        assert!(
            app.state.ui.reading,
            "an older response cannot finish the new read"
        );
        app.dispatch(UiCommand::CancelModal);
        assert!(
            !app.state.ui.reading,
            "local cancellation does not leave a pending view"
        );
    }
}
