use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const BOOTSTRAP_LIFETIME: Duration = Duration::from_secs(120);
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
const SESSION_IDLE: Duration = Duration::from_secs(15 * 60);

pub fn secret() -> std::io::Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| std::io::Error::other("OS randomness unavailable"))?;
    Ok(evertrace_domain::evidence::hex(&bytes))
}

fn same(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

struct Session {
    cookie: String,
    csrf: String,
    created: Instant,
    seen: Instant,
}

/// One browser session per bridge. Tabs share its host-only HttpOnly cookie;
/// independent bridge launches use different ports, cookie names and secrets.
pub struct Sessions {
    bootstrap: Option<(String, Instant)>,
    session: Option<Session>,
}

impl Sessions {
    pub fn new(token: String) -> Self {
        Self {
            bootstrap: Some((token, Instant::now())),
            session: None,
        }
    }

    pub fn exchange(&mut self, candidate: &str) -> std::io::Result<Option<(String, String)>> {
        let valid = self.bootstrap.as_ref().is_some_and(|(token, created)| {
            created.elapsed() < BOOTSTRAP_LIFETIME && same(token, candidate)
        });
        if !valid {
            return Ok(None);
        }
        let cookie = secret()?;
        let csrf = secret()?;
        self.bootstrap = None;
        self.session = Some(Session {
            cookie: cookie.clone(),
            csrf: csrf.clone(),
            created: Instant::now(),
            seen: Instant::now(),
        });
        Ok(Some((cookie, csrf)))
    }

    pub fn authenticate(&mut self, cookie: &str, csrf: Option<&str>) -> Option<String> {
        if self.session.as_ref().is_some_and(|session| {
            session.created.elapsed() >= SESSION_LIFETIME || session.seen.elapsed() >= SESSION_IDLE
        }) {
            self.session = None;
        }
        let session = self.session.as_mut()?;
        if !same(&session.cookie, cookie) || csrf.is_some_and(|token| !same(&session.csrf, token)) {
            return None;
        }
        session.seen = Instant::now();
        Some(session.csrf.clone())
    }

    pub fn logout(&mut self) {
        self.session = None;
    }
}
