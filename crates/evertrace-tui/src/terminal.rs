use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use std::io::{self, stdout};

trait TerminalOps: Send {
    fn enable_raw(&mut self) -> io::Result<()>;
    fn enter_alternate(&mut self) -> io::Result<()>;
    fn hide_cursor(&mut self) -> io::Result<()>;
    fn show_cursor(&mut self) -> io::Result<()>;
    fn leave_alternate(&mut self) -> io::Result<()>;
    fn disable_raw(&mut self) -> io::Result<()>;
}

struct CrosstermOps;

impl TerminalOps for CrosstermOps {
    fn enable_raw(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }
    fn enter_alternate(&mut self) -> io::Result<()> {
        execute!(stdout(), EnterAlternateScreen)
    }
    fn hide_cursor(&mut self) -> io::Result<()> {
        execute!(stdout(), Hide)
    }
    fn show_cursor(&mut self) -> io::Result<()> {
        execute!(stdout(), Show)
    }
    fn leave_alternate(&mut self) -> io::Result<()> {
        execute!(stdout(), LeaveAlternateScreen)
    }
    fn disable_raw(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
}

pub struct TerminalGuard {
    ops: Box<dyn TerminalOps>,
    active: bool,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        Self::enter_with(Box::new(CrosstermOps))
    }

    fn enter_with(mut ops: Box<dyn TerminalOps>) -> io::Result<Self> {
        ops.enable_raw()?;
        if let Err(error) = ops.enter_alternate().and_then(|()| ops.hide_cursor()) {
            let _ = restore_all(ops.as_mut());
            return Err(error);
        }
        Ok(Self { ops, active: true })
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let result = restore_all(self.ops.as_mut());
        if result.is_ok() {
            self.active = false;
        }
        result
    }
}

fn restore_all(ops: &mut dyn TerminalOps) -> io::Result<()> {
    let mut first = None;
    for result in [ops.show_cursor(), ops.leave_alternate(), ops.disable_raw()] {
        if let Err(error) = result
            && first.is_none()
        {
            first = Some(error);
        }
    }
    first.map_or(Ok(()), Err)
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockOps {
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail: Option<&'static str>,
    }

    impl MockOps {
        fn call(&self, name: &'static str) -> io::Result<()> {
            self.calls.lock().unwrap().push(name);
            if self.fail == Some(name) {
                Err(io::Error::other(name))
            } else {
                Ok(())
            }
        }
    }

    impl TerminalOps for MockOps {
        fn enable_raw(&mut self) -> io::Result<()> {
            self.call("raw")
        }
        fn enter_alternate(&mut self) -> io::Result<()> {
            self.call("enter")
        }
        fn hide_cursor(&mut self) -> io::Result<()> {
            self.call("hide")
        }
        fn show_cursor(&mut self) -> io::Result<()> {
            self.call("show")
        }
        fn leave_alternate(&mut self) -> io::Result<()> {
            self.call("leave")
        }
        fn disable_raw(&mut self) -> io::Result<()> {
            self.call("disable")
        }
    }

    fn mock(fail: Option<&'static str>) -> (Box<dyn TerminalOps>, Arc<Mutex<Vec<&'static str>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Box::new(MockOps {
                calls: calls.clone(),
                fail,
            }),
            calls,
        )
    }

    #[test]
    fn drop_and_panic_restore_terminal() {
        for panic in [false, true] {
            let (ops, calls) = mock(None);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = TerminalGuard::enter_with(ops).unwrap();
                assert!(!panic, "test panic");
            }));
            assert_eq!(result.is_err(), panic);
            assert_eq!(
                *calls.lock().unwrap(),
                ["raw", "enter", "hide", "show", "leave", "disable"]
            );
        }
    }

    #[test]
    fn partial_enter_and_restore_failure_attempt_every_cleanup() {
        let (ops, calls) = mock(Some("hide"));
        assert!(TerminalGuard::enter_with(ops).is_err());
        assert_eq!(
            *calls.lock().unwrap(),
            ["raw", "enter", "hide", "show", "leave", "disable"]
        );

        let (ops, calls) = mock(Some("show"));
        let mut guard = TerminalGuard::enter_with(ops).unwrap();
        assert!(guard.restore().is_err());
        assert_eq!(
            *calls.lock().unwrap(),
            ["raw", "enter", "hide", "show", "leave", "disable"]
        );
        drop(guard);
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "raw", "enter", "hide", "show", "leave", "disable", "show", "leave", "disable"
            ]
        );
    }
}
