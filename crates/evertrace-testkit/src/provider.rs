//! Minimal one-request HTTP stub for S26 provider boundary tests.

use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

pub struct ProviderStub {
    pub base_url: String,
    requests: oneshot::Receiver<Vec<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl ProviderStub {
    pub async fn once(status: u16, body: Vec<u8>) -> Self {
        Self::once_delayed(status, body, std::time::Duration::ZERO).await
    }

    pub async fn once_delayed(status: u16, body: Vec<u8>, delay: std::time::Duration) -> Self {
        Self::repeat_delayed(status, body, delay, 1).await
    }

    pub async fn repeat(status: u16, body: Vec<u8>, count: usize) -> Self {
        Self::repeat_delayed(status, body, std::time::Duration::ZERO, count).await
    }

    async fn repeat_delayed(
        status: u16,
        body: Vec<u8>,
        delay: std::time::Duration,
        count: usize,
    ) -> Self {
        assert!(count > 0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests_tx, requests) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut captured = Vec::with_capacity(count);
            for _ in 0..count {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    let Some(header_end) = bytes.windows(4).position(|value| value == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                        })
                        .unwrap_or(0);
                    if bytes.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                captured.push(bytes);
                tokio::time::sleep(delay).await;
                let reason = if status == 200 { "OK" } else { "ERROR" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                }
            }
            let _ = requests_tx.send(captured);
        });
        Self {
            base_url: endpoint_base(address),
            requests,
            task,
        }
    }

    pub async fn finish(self) -> Vec<u8> {
        let mut requests = self.requests.await.unwrap();
        self.task.await.unwrap();
        assert_eq!(requests.len(), 1);
        requests.remove(0)
    }

    pub async fn finish_all(self) -> Vec<Vec<u8>> {
        let requests = self.requests.await.unwrap();
        self.task.await.unwrap();
        requests
    }
}

fn endpoint_base(address: SocketAddr) -> String {
    format!("http://{address}/v1")
}
