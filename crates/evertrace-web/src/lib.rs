#![forbid(unsafe_code)]
#![deny(warnings)]

//! Foreground browser transport. All domain reads go through the owned daemon
//! socket; this crate never opens a store, CAS path or host transcript.
mod server;
mod session;

use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient,
    command::Command,
    dto::{ClientKind, HealthMode},
    response::Response,
};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};

struct Backend {
    socket: PathBuf,
    config_hash: String,
}

impl Backend {
    async fn request(&self, command: Command) -> Result<Response, ()> {
        timeout(Duration::from_secs(5), async {
            let mut client = LocalClient::connect(
                &self.socket,
                env!("CARGO_PKG_VERSION"),
                ClientKind::Web,
                Duration::from_secs(2),
            )
            .await
            .map_err(|_| ())?;
            let health = client
                .request(RequestId::new_v7(), Command::Health)
                .await
                .map_err(|_| ())?;
            match &health {
                Response::Health(value)
                    if value.validate()
                        && value.mode == HealthMode::Normal
                        && value.effective_config_hash == self.config_hash => {}
                _ => return Err(()),
            }
            if matches!(command, Command::Health) {
                return Ok(health);
            }
            client
                .request(RequestId::new_v7(), command)
                .await
                .map_err(|_| ())
        })
        .await
        .map_err(|_| ())?
    }
}

struct Bridge {
    backend: Backend,
    origin: String,
    host: String,
    cookie_name: String,
    sessions: Mutex<session::Sessions>,
}

pub async fn run(
    socket: PathBuf,
    config_hash: String,
    port: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    let backend = Backend {
        socket,
        config_hash,
    };
    backend.request(Command::Health).await.map_err(|_| {
        "WebUI requires the matching daemon and active configuration; start evertrace --daemon first"
    })?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.unwrap_or(0))).await?;
    let host = listener.local_addr()?.to_string();
    let origin = format!("http://{host}");
    let token = session::secret()?;
    let bridge = Arc::new(Bridge {
        backend,
        origin: origin.clone(),
        host,
        cookie_name: format!("evertrace_web_{}", listener.local_addr()?.port()),
        sessions: Mutex::new(session::Sessions::new(token.clone())),
    });
    // This is a user-visible, short-lived credential, not a diagnostic event.
    println!("WebUI: {origin}/#bootstrap={token}");
    println!("Local HTTP only. Keep this link private; Ctrl-C closes the bridge, not the daemon.");
    drop(token);
    let permits = Arc::new(Semaphore::new(16));
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if !peer.ip().is_loopback() { continue; }
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let bridge = bridge.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |request| server::serve(request, bridge.clone()));
                    let mut http = http1::Builder::new();
                    // The outer deadline bounds headers, body and response together.
                    http.keep_alive(false).header_read_timeout(None).max_headers(32).max_buf_size(16 * 1024);
                    let _ = timeout(Duration::from_secs(10), http.serve_connection(TokioIo::new(stream), service)).await;
                });
            }
        }
    }
    drop(listener);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
