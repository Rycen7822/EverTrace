use crate::Bridge;
use evertrace_protocol::{
    command::Command,
    dto::{
        HumanExplorerListSelection, HumanGovernanceRequest, HumanGovernanceResponse,
        HumanReadRequest, HumanSurface, MAX_FRAME_SIZE,
    },
    error::{ErrorCode, ProtocolError},
    response::Response as DaemonResponse,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
};
use serde::Deserialize;
use serde_json::json;
use std::{convert::Infallible, sync::Arc};

type Reply = Response<Full<Bytes>>;
const MAX_BODY: usize = 8192;

fn reply(status: StatusCode, mime: &'static str, body: impl Into<Bytes>) -> Reply {
    Response::builder().status(status)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Frame-Options", "DENY")
        .header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        .body(Full::new(body.into())).expect("fixed response headers")
}

fn json_reply(status: StatusCode, value: &impl serde::Serialize) -> Reply {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= MAX_FRAME_SIZE => reply(status, "application/json", bytes),
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "response_unavailable"),
    }
}

fn error(status: StatusCode, code: &'static str) -> Reply {
    reply(
        status,
        "application/json",
        format!("{{\"error\":\"{code}\"}}"),
    )
}

fn single<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    let mut values = headers.get_all(key).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for pair in single(headers, "cookie")?.split(';') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if key == name {
            if found.is_some() || value.len() != 64 {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

fn cookie_header(bridge: &Bridge, value: &str, age: u32) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}",
        bridge.cookie_name
    ))
    .expect("generated cookie")
}

fn unauthorized(bridge: &Bridge) -> Reply {
    let mut response = error(StatusCode::UNAUTHORIZED, "session_expired");
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie_header(bridge, "", 0));
    response
}

fn static_asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    Some(match path {
        "/" | "/index.html" => (
            "text/html; charset=utf-8",
            include_bytes!("../assets/index.html"),
        ),
        "/styles.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../assets/styles.css"),
        ),
        "/app.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../assets/app.js"),
        ),
        "/assets/fonts/IBMPlexSans-Regular.ttf" => (
            "font/ttf",
            include_bytes!("../assets/assets/fonts/IBMPlexSans-Regular.ttf"),
        ),
        "/assets/fonts/IBMPlexSans-Medium.ttf" => (
            "font/ttf",
            include_bytes!("../assets/assets/fonts/IBMPlexSans-Medium.ttf"),
        ),
        "/assets/fonts/IBMPlexSans-Semibold.ttf" => (
            "font/ttf",
            include_bytes!("../assets/assets/fonts/IBMPlexSans-Semibold.ttf"),
        ),
        "/assets/fonts/IBMPlexMono-Regular.ttf" => (
            "font/ttf",
            include_bytes!("../assets/assets/fonts/IBMPlexMono-Regular.ttf"),
        ),
        "/assets/fonts/IBMPlexMono-Medium.ttf" => (
            "font/ttf",
            include_bytes!("../assets/assets/fonts/IBMPlexMono-Medium.ttf"),
        ),
        "/assets/fonts/ibmplexsans-OFL.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("../assets/assets/fonts/ibmplexsans-OFL.txt"),
        ),
        "/assets/fonts/ibmplexmono-OFL.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("../assets/assets/fonts/ibmplexmono-OFL.txt"),
        ),
        _ => return None,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    token: String,
}

async fn handle(request: Request<Incoming>, bridge: &Bridge) -> Reply {
    let headers = request.headers();
    for key in [
        "host",
        "origin",
        "sec-fetch-site",
        "x-evertrace-web",
        "x-evertrace-csrf",
        "cookie",
        "content-type",
    ] {
        if headers.get_all(key).iter().count() > 1 {
            return error(StatusCode::BAD_REQUEST, "ambiguous_headers");
        }
    }
    if single(headers, "host") != Some(bridge.host.as_str())
        || request.uri().authority().is_some()
        || request.uri().scheme().is_some()
        || request.uri().query().is_some()
        || (headers.contains_key("origin")
            && single(headers, "origin") != Some(bridge.origin.as_str()))
    {
        return error(StatusCode::FORBIDDEN, "origin_rejected");
    }
    let path = request.uri().path().to_owned();
    if !path.starts_with("/api/") {
        if !matches!(
            single(headers, "sec-fetch-site"),
            None | Some("same-origin" | "none")
        ) {
            return error(StatusCode::FORBIDDEN, "cross_site_rejected");
        }
        if request.method() != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "method_rejected");
        }
        return match static_asset(&path) {
            Some((mime, bytes)) => reply(StatusCode::OK, mime, Bytes::from_static(bytes)),
            None => error(StatusCode::NOT_FOUND, "not_found"),
        };
    }
    if single(headers, "x-evertrace-web") != Some("1")
        || !matches!(
            single(headers, "sec-fetch-site"),
            None | Some("same-origin")
        )
    {
        return error(StatusCode::FORBIDDEN, "cross_site_rejected");
    }
    let post = request.method() == Method::POST;
    if post
        && (single(headers, "origin") != Some(bridge.origin.as_str())
            || single(headers, "content-type") != Some("application/json"))
    {
        return error(StatusCode::FORBIDDEN, "request_rejected");
    }
    if !matches!(
        (request.method(), path.as_str()),
        (
            &Method::POST,
            "/api/bootstrap" | "/api/logout" | "/api/read"
        ) | (&Method::GET, "/api/session" | "/api/status")
    ) {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method_rejected");
    }
    let token = cookie(headers, &bridge.cookie_name);
    let csrf = single(headers, "x-evertrace-csrf").map(str::to_owned);
    if path != "/api/bootstrap" {
        let Some(token) = token.as_deref() else {
            return unauthorized(bridge);
        };
        let Ok(mut sessions) = bridge.sessions.lock() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "session_unavailable");
        };
        if post && csrf.is_none() {
            return error(StatusCode::FORBIDDEN, "csrf_rejected");
        }
        let Some(current_csrf) =
            sessions.authenticate(token, if post { csrf.as_deref() } else { None })
        else {
            return unauthorized(bridge);
        };
        if path == "/api/session" {
            return json_reply(StatusCode::OK, &json!({"csrf": current_csrf}));
        }
        if path == "/api/logout" {
            sessions.logout();
            let mut response = json_reply(StatusCode::OK, &json!({"closed": true}));
            response
                .headers_mut()
                .insert(header::SET_COOKIE, cookie_header(bridge, "", 0));
            return response;
        }
    }
    // Both JSON read requests and bootstrap have a small hard body bound. No
    // arbitrary protocol command, path, action or caller role is accepted.
    let command = if path == "/api/status" {
        Command::Health
    } else {
        let collected = match Limited::new(request.into_body(), MAX_BODY).collect().await {
            Ok(value) => value.to_bytes(),
            Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body_rejected"),
        };
        if path == "/api/bootstrap" {
            let Ok(body) = serde_json::from_slice::<Bootstrap>(&collected) else {
                return error(StatusCode::BAD_REQUEST, "invalid_bootstrap");
            };
            let Ok(mut sessions) = bridge.sessions.lock() else {
                return error(StatusCode::INTERNAL_SERVER_ERROR, "session_unavailable");
            };
            return match sessions.exchange(&body.token) {
                Ok(Some((cookie, csrf))) => {
                    let mut response = json_reply(StatusCode::OK, &json!({"csrf": csrf}));
                    response.headers_mut().insert(
                        header::SET_COOKIE,
                        cookie_header(bridge, &cookie, 8 * 60 * 60),
                    );
                    response
                }
                Ok(None) => error(StatusCode::UNAUTHORIZED, "bootstrap_expired"),
                Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "session_unavailable"),
            };
        }
        let Ok(read) = serde_json::from_slice::<HumanReadRequest>(&collected) else {
            return error(StatusCode::BAD_REQUEST, "invalid_read");
        };
        if !matches!(
            &read,
            HumanReadRequest::List {
                surface: HumanSurface::Explorer,
                system_selection: None,
                explorer_selection: Some(HumanExplorerListSelection::Memories),
                ..
            } | HumanReadRequest::Detail {
                surface: HumanSurface::Explorer,
                ..
            } | HumanReadRequest::Compare { .. }
                | HumanReadRequest::Related {
                    relation: evertrace_protocol::dto::HumanRelationKind::ObjectSources
                        | evertrace_protocol::dto::HumanRelationKind::ObjectRevisions,
                    ..
                }
        ) {
            return error(StatusCode::BAD_REQUEST, "read_unavailable");
        }
        let request = HumanGovernanceRequest::Read { request: read };
        if !request.validate() {
            return error(StatusCode::BAD_REQUEST, "invalid_read");
        }
        Command::HumanGovernance(request)
    };
    let result = bridge.backend.request(command).await;
    // Logout or expiry during the bounded daemon read must not deliver content.
    let authorized = bridge.sessions.lock().ok().is_some_and(|mut sessions| {
        token
            .as_deref()
            .is_some_and(|token| sessions.authenticate(token, None).is_some())
    });
    if !authorized {
        return unauthorized(bridge);
    }
    match result {
        Ok(DaemonResponse::Health(health)) => json_reply(
            StatusCode::OK,
            &json!({
                "connected": true, "protocol_version": health.protocol_version,
                "mode": health.mode, "algorithm_revision": health.algorithm_revision,
            }),
        ),
        Ok(DaemonResponse::HumanGovernance(
            body @ (HumanGovernanceResponse::Snapshot { .. }
            | HumanGovernanceResponse::Conflict { .. }),
        )) => json_reply(StatusCode::OK, &body),
        Err(ProtocolError::Wire(ErrorCode::InvalidInput)) => {
            error(StatusCode::BAD_REQUEST, "invalid_read")
        }
        Err(ProtocolError::Wire(ErrorCode::Untrusted)) => {
            error(StatusCode::FORBIDDEN, "read_denied")
        }
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "daemon_unavailable"),
    }
}

pub async fn serve(request: Request<Incoming>, bridge: Arc<Bridge>) -> Result<Reply, Infallible> {
    Ok(handle(request, &bridge).await)
}
