use evertrace_tui::{App, AppEvent, AppEventSender, ConnectionState, Route, UiCommand};

#[test]
fn three_pane_and_compact_shell_match_golden() {
    let wide = evertrace_tui::headless_render(100, 30).unwrap();
    let compact = evertrace_tui::headless_render(60, 20).unwrap();
    assert_eq!(
        wide,
        include_str!("../../../fixtures/tui/s30/wide.txt").trim_end()
    );
    assert_eq!(
        compact,
        include_str!("../../../fixtures/tui/s30/compact.txt").trim_end()
    );
}

#[tokio::test]
async fn bounded_bus_processes_every_event_and_render_remains_responsive() {
    let (sender, mut receiver) = AppEventSender::channel();
    let producer = tokio::spawn(async move {
        for index in 0..1_000 {
            sender
                .send(AppEvent::Resize(60 + (index % 2), 20))
                .await
                .unwrap();
        }
    });
    let consumer = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
        let mut app = App::new();
        for _ in 0..1_000 {
            app.handle(receiver.recv().await.unwrap());
            let frame = evertrace_tui::headless_render(60, 20).unwrap();
            assert!(frame.contains("No inbox items"));
        }
        app.handle(AppEvent::Disconnected);
        app.dispatch(UiCommand::Navigate(Route::Explorer));
        assert_eq!(app.state().route, Route::Explorer);
        assert_eq!(app.state().shell.connection, ConnectionState::Disconnected);
    })
    .await;
    assert!(consumer.is_ok());
    producer.await.unwrap();
}
