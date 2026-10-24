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
    received: std::sync::Arc<tokio::sync::Notify>,
}

enum StubBody {
    Repeat(Vec<u8>),
    Methods {
        source: Vec<u8>,
        review: Vec<u8>,
        summary: Vec<u8>,
    },
}

impl ProviderStub {
    pub async fn once(status: u16, body: Vec<u8>) -> Self {
        Self::once_delayed(status, body, std::time::Duration::ZERO).await
    }

    pub async fn once_delayed(status: u16, body: Vec<u8>, delay: std::time::Duration) -> Self {
        Self::repeat_delayed(status, body, delay, 1).await
    }

    #[allow(dead_code)] // Not every test target exercises in-flight admission.
    pub async fn once_paused(status: u16, body: Vec<u8>) -> (Self, oneshot::Sender<()>) {
        let (release, gate) = oneshot::channel();
        (
            Self::serve(
                status,
                StubBody::Repeat(body),
                std::time::Duration::ZERO,
                1,
                Some(gate),
                false,
            )
            .await,
            release,
        )
    }

    #[allow(dead_code)]
    pub async fn wait_received(&self) {
        self.received.notified().await;
    }

    pub async fn repeat(status: u16, body: Vec<u8>, count: usize) -> Self {
        Self::repeat_delayed(status, body, std::time::Duration::ZERO, count).await
    }

    #[allow(dead_code)]
    pub async fn recovering(body: Vec<u8>) -> Self {
        Self::serve(
            200,
            StubBody::Repeat(body),
            std::time::Duration::ZERO,
            2,
            None,
            true,
        )
        .await
    }

    pub async fn methods(source: Vec<u8>, review: Vec<u8>, summary: Vec<u8>, count: usize) -> Self {
        Self::serve(
            200,
            StubBody::Methods {
                source,
                review,
                summary,
            },
            std::time::Duration::ZERO,
            count,
            None,
            false,
        )
        .await
    }

    async fn repeat_delayed(
        status: u16,
        body: Vec<u8>,
        delay: std::time::Duration,
        count: usize,
    ) -> Self {
        Self::serve(status, StubBody::Repeat(body), delay, count, None, false).await
    }

    async fn serve(
        status: u16,
        body: StubBody,
        delay: std::time::Duration,
        count: usize,
        mut gate: Option<oneshot::Receiver<()>>,
        fail_first: bool,
    ) -> Self {
        assert!(count > 0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests_tx, requests) = oneshot::channel();
        let received = std::sync::Arc::new(tokio::sync::Notify::new());
        let notify = std::sync::Arc::clone(&received);
        // Summary fixtures also service the independent method producer with
        // a closed no-op. Preserve every request in finish_all for call audits.
        let summary = serde_json::from_slice::<serde_json::Value>(match &body {
            StubBody::Repeat(body) => body,
            StubBody::Methods { .. } => &[],
        })
        .ok()
        .and_then(|envelope| {
            envelope["choices"][0]["message"]["content"]
                .as_str()
                .map(str::to_owned)
        })
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .is_some_and(|content| content.get("candidates").is_some());
        let task = tokio::spawn(async move {
            let mut captured = Vec::with_capacity(count);
            let mut index = 0;
            while index < count {
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
                let method_no_op = summary
                    && String::from_utf8_lossy(&bytes)
                        .contains("Extract at most one nontrivial reusable method");
                let selected_body = match &body {
                    StubBody::Repeat(body) => body.as_slice(),
                    StubBody::Methods {
                        source,
                        review,
                        summary,
                    } => {
                        let request = String::from_utf8_lossy(&bytes);
                        if request.contains("Extract at most one nontrivial reusable method") {
                            source
                        } else if request.contains("Review one Procedure") {
                            review
                        } else {
                            summary
                        }
                    }
                };
                captured.push(bytes);
                if !method_no_op {
                    notify.notify_one();
                }
                if !method_no_op && let Some(gate) = gate.take() {
                    let _ = gate.await;
                }
                tokio::time::sleep(delay).await;
                let status = if method_no_op {
                    200
                } else if fail_first && index == 0 {
                    503
                } else {
                    status
                };
                let no_op = br#"{"choices":[{"message":{"content":"{\"operation\":\"no_op\"}"}}],"usage":{"prompt_tokens":17,"completion_tokens":5}}"#;
                let body = if method_no_op {
                    no_op.as_slice()
                } else {
                    selected_body
                };
                let reason = if status == 200 { "OK" } else { "ERROR" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(body).await;
                    let _ = stream.shutdown().await;
                }
                if !method_no_op {
                    index += 1;
                }
            }
            let _ = requests_tx.send(captured);
        });
        Self {
            base_url: endpoint_base(address),
            requests,
            task,
            received,
        }
    }

    pub async fn finish(self) -> Vec<u8> {
        let mut requests = self.requests.await.unwrap();
        self.task.await.unwrap();
        if requests.len() > 1 {
            requests.retain(|request| {
                !String::from_utf8_lossy(request)
                    .contains("Extract at most one nontrivial reusable method")
            });
        }
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
