use ratatui::layout::{Constraint, Direction, Layout, Rect};
pub struct ShellLayout {
    pub header: Rect,
    pub nav: Rect,
    pub list: Rect,
    pub inspector: Rect,
    pub status: Rect,
    pub hints: Rect,
    pub compact: bool,
}
pub fn shell(a: Rect) -> ShellLayout {
    let r = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(a);
    if a.width >= 100 && a.height >= 30 {
        let c = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(18),
                Constraint::Percentage(52),
                Constraint::Min(24),
            ])
            .split(r[1]);
        ShellLayout {
            header: r[0],
            nav: c[0],
            list: c[1],
            inspector: c[2],
            status: r[2],
            hints: r[3],
            compact: false,
        }
    } else {
        ShellLayout {
            header: r[0],
            nav: r[1],
            list: r[1],
            inspector: r[1],
            status: r[2],
            hints: r[3],
            compact: true,
        }
    }
}
