use crate::{
    AppEvent, AppEventSender, AppState, ConnectionState, UiCommand, client, components, keymap,
    layout, views,
};
use crossterm::event::{self, Event};
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
            AppEvent::Key(key) => self.dispatch(keymap::command(key)),
            AppEvent::Health(health) => {
                self.state.shell.health = Some(health);
                self.state.shell.connection = ConnectionState::Connected;
                UiCommand::None
            }
            AppEvent::Pending(count) => {
                self.state.shell.pending = count;
                UiCommand::None
            }
            AppEvent::Disconnected => {
                self.state.shell.connection = ConnectionState::Disconnected;
                UiCommand::None
            }
            AppEvent::Notification(_) => {
                self.state.shell.connection = ConnectionState::ServerStopping;
                UiCommand::None
            }
            AppEvent::Shutdown => self.dispatch(UiCommand::Quit),
            AppEvent::Tick | AppEvent::Resize(_, _) => UiCommand::None,
        }
    }

    pub fn dispatch(&mut self, command: UiCommand) -> UiCommand {
        match command {
            UiCommand::Navigate(route) => self.state.route = route,
            UiCommand::Quit => self.state.quit = true,
            UiCommand::Refresh | UiCommand::None => {}
        }
        command
    }

    pub fn render(&self, frame: &mut Frame) {
        let palette = &crate::theme::EVER_OS;
        let shell = layout::shell(frame.area());
        frame.render_widget(
            components::header().style(Style::default().fg(palette.ink).bg(palette.background)),
            shell.header,
        );
        if shell.compact {
            views::render(frame, shell.list, self.state.route);
        } else {
            frame.render_widget(components::navigation(self.state.route), shell.nav);
            views::render(frame, shell.list, self.state.route);
            frame.render_widget(
                components::inspector()
                    .style(Style::default().fg(palette.muted).bg(palette.surface)),
                shell.inspector,
            );
        }
        frame.render_widget(components::status_bar(&self.state.shell), shell.status);
        frame.render_widget(
            Paragraph::new("1 Inbox  2 Explorer  3 System  r refresh  q quit")
                .style(Style::default().fg(palette.muted)),
            shell.hints,
        );
        if self.state.shell.pending > 0 {
            let area = centered(frame.area(), 28, 3);
            let (clear, modal) = components::modal();
            frame.render_widget(clear, area);
            frame.render_widget(modal, area);
        }
    }
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
            if command == UiCommand::Refresh {
                let _ = ui_commands.try_send(client::ClientCommand::Refresh);
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
