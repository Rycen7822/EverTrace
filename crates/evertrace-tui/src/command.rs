use crate::Route;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiCommand {
    Navigate(Route),
    Refresh,
    Quit,
    None,
}
