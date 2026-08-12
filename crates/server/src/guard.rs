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

/// The caller's address. In-process callers (tests, embedded use)
/// have none, and are not rate limited — there is no anonymous
/// network in front of them to protect against.
///
/// Behind a reverse proxy every connection appears to come from the
/// proxy, which would put every caller in one bucket. The forwarded
/// header fixes that, but only where it can be believed: a header
/// anyone can set is worse than no header at all, so it is read only
/// when the operator says something trustworthy sets it.
pub struct ClientIp(pub Option<IpAddr>);

/// Whose word to take for the caller's address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProxyTrust {
    /// Only the connection itself.
    Connection,
    /// The last hop recorded in X-Forwarded-For, which is the one the
    /// trusted proxy appended and the only one a client cannot forge.
    ForwardedHeader,
}

/// Read the address a trusted proxy recorded. The rightmost entry is
/// the one the nearest proxy added; entries further left were supplied
/// by whatever came before it, including the client.
fn forwarded_for(parts: &axum::http::request::Parts) -> Option<IpAddr> {
    parts
        .headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .rsplit(',')
        .map(str::trim)
        .find_map(|hop| hop.parse().ok())
}

impl axum::extract::FromRequestParts<crate::AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        let connected = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|connected| connected.0.ip());
        Ok(ClientIp(match state.proxy_trust() {
            ProxyTrust::ForwardedHeader => forwarded_for(parts).or(connected),
            ProxyTrust::Connection => connected,
        }))
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
    fn the_forwarded_address_is_read_from_the_nearest_hop() {
        let request = axum::http::Request::builder()
            // A client can put anything on the left; only the last
            // entry was written by the proxy we trust.
            .header("x-forwarded-for", "10.0.0.1, 198.51.100.9, 203.0.113.4")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        assert_eq!(
            forwarded_for(&parts),
            Some("203.0.113.4".parse().unwrap()),
            "the rightmost hop is the one a client cannot forge"
        );

        let empty = axum::http::Request::builder().body(()).unwrap();
        let (parts, ()) = empty.into_parts();
        assert_eq!(forwarded_for(&parts), None);
    }

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
