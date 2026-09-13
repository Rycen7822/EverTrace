use ratatui::layout::{Constraint, Direction, Layout, Rect};
#[derive(Clone, Default)]
pub struct ShellLayout {
    pub header: Rect,
    pub nav: Rect,
    pub tools: Rect,
    pub actions: Rect,
    pub list: Rect,
    pub inspector: Rect,
    pub status: Rect,
    pub hints: Rect,
    pub compact: bool,
}
pub(crate) fn responsive(a: Rect, detail: bool, zoom: bool, detail_focus: bool) -> ShellLayout {
    let r = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(a);
    if detail && !zoom && a.width >= 120 && a.height >= 30 {
        let c = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(r[3]);
        ShellLayout {
            header: r[0],
            nav: r[1],
            tools: r[2],
            actions: r[4],
            list: c[0],
            inspector: c[1],
            status: r[5],
            hints: r[6],
            compact: false,
        }
    } else {
        ShellLayout {
            header: r[0],
            nav: r[1],
            tools: r[2],
            actions: r[4],
            list: if detail && (!zoom || detail_focus) {
                Rect::default()
            } else {
                r[3]
            },
            inspector: if detail && (!zoom || detail_focus) {
                r[3]
            } else {
                Rect::default()
            },
            status: r[5],
            hints: r[6],
            compact: true,
        }
    }
}
