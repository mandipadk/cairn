//! What a forge on the open internet needs before it gets there.
//!
//! Two things live here. Response headers that hold whatever the
//! browser renders to the narrowest useful behaviour, and a limiter on
//! the one endpoint an anonymous stranger can hammer: sign-in.
//!
//! Everything else that matters is enforced deeper down — capabilities
//! in the core, body size at the routes, subprocess timeouts in the git
//! layer — because a guard at the edge only ever catches what happens
//! to pass through it.

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The pages serve their own CSS from the same origin and run no
/// script at all, so the policy can say exactly that.
const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self' data:; \
                   form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

/// A fixed-window limiter for sign-in attempts, keyed by source
/// address. Deliberately small: it exists to make credential guessing
/// pointless, not to be a traffic shaper.
#[derive(Clone)]
pub struct LoginLimiter {
    attempts: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    allowed: u32,
    window: Duration,
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(60))
    }
}

impl LoginLimiter {
    pub fn new(allowed: u32, window: Duration) -> Self {
        LoginLimiter {
            attempts: Arc::new(Mutex::new(HashMap::new())),
            allowed,
            window,
        }
    }

    /// Record an attempt; false means this caller has had enough.
    pub fn accept(&self, from: IpAddr) -> bool {
        let mut attempts = match self.attempts.lock() {
            Ok(attempts) => attempts,
            // A poisoned lock must not lock everyone out of signing in.
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        attempts.retain(|_, (_, started)| now.duration_since(*started) < self.window);
        let entry = attempts.entry(from).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= self.allowed
    }
}

/// The caller's address, when the server was started in a way that
/// knows it. In-process callers (tests, embedded use) have none, and
/// are not rate limited — there is no anonymous network in front of
/// them to protect against.
pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|connected| connected.0.ip()),
        ))
    }
}

pub fn too_many_attempts() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, "60")],
        "Too many sign-in attempts. Wait a minute and try again.",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caller_gets_its_allowance_and_no_more() {
        let limiter = LoginLimiter::new(3, Duration::from_secs(60));
        let caller: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.accept(caller));
        assert!(limiter.accept(caller));
        assert!(limiter.accept(caller));
        assert!(!limiter.accept(caller), "the fourth attempt is refused");
        // One caller's noise never costs another their allowance.
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(limiter.accept(other));
    }

    #[test]
    fn the_window_forgives() {
        let limiter = LoginLimiter::new(1, Duration::from_millis(20));
        let caller: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(limiter.accept(caller));
        assert!(!limiter.accept(caller));
        std::thread::sleep(Duration::from_millis(30));
        assert!(limiter.accept(caller), "a new window is a clean slate");
    }
}
