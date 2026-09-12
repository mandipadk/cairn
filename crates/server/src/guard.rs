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
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The pages serve their own CSS and one small script from the same
/// origin, and fetch only from it, so the policy can say exactly that.
const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self' data:; \
                   script-src 'self'; connect-src 'self'; \
                   form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        // Not `no-referrer`: under that policy a browser sends
        // `Origin: null` on our own forms too, and the write guard below
        // could no longer tell our pages from anyone else's.
        (header::REFERRER_POLICY, "same-origin"),
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

/// Refuse a write that a browser sent from somewhere else.
///
/// The session cookie is SameSite=Lax, which already keeps a foreign
/// page's form from carrying it. This is the second lock: a browser
/// says where a request came from (`Sec-Fetch-Site`, and `Origin` on
/// any POST), and a write claiming to come from another site is refused
/// before any handler sees it. `Sec-Fetch-Site: same-origin` is the
/// browser's own word and settles it; `Origin` decides only when the
/// browser did not say. Git clients, curl and agents send neither header
/// and are unaffected; they authenticate with a bearer token, which no
/// other site can attach.
pub async fn same_origin_writes(request: Request, next: Next) -> Response {
    let method = request.method();
    let reads = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if !reads {
        let headers = request.headers();
        let fetch_site = headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        match fetch_site {
            "cross-site" => {
                return refused(request.uri().path(), "cross-site writes are not accepted");
            }
            "same-origin" => {}
            _ => {
                // An older browser, or a sibling site: `Origin` has to
                // name us. "null" never does - it is what a browser sends
                // from a sandboxed or opaque context, none of which is ours.
                if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
                    let host = headers
                        .get(header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                        .or_else(|| request.uri().authority().map(|a| a.to_string()));
                    match host {
                        Some(host) if origin_matches(origin, &host) => {}
                        _ => {
                            return refused(
                                request.uri().path(),
                                "this write did not come from here",
                            );
                        }
                    }
                }
            }
        }
    }
    next.run(request).await
}

/// `Origin` carries a scheme and never a path; `Host` carries neither.
fn origin_matches(origin: &str, host: &str) -> bool {
    origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .eq_ignore_ascii_case(host)
}

/// The origin check's refusal, in the shape its reader expects: the
/// API's on the API, and a page for a browser — which is who sends
/// the headers that fail this check.
fn refused(path: &str, why: &'static str) -> Response {
    if path.starts_with("/api/") || path.starts_with("/git/") {
        return crate::error::ApiError::new(StatusCode::FORBIDDEN, "forbidden", why)
            .into_response();
    }
    (
        StatusCode::FORBIDDEN,
        [(
            axum::http::HeaderName::from_static(crate::web::FALLBACK),
            "not-from-here",
        )],
        why,
    )
        .into_response()
}

/// Whether a request is the operator's door: what registers people,
/// hands out authority, sets what an owner may have, reads the
/// waitlist and the reports, invites, or spends the operator's own
/// credentials. When the forge serves that door on a loopback
/// listener, the public listener refuses these, with or without a
/// token — a token that travelled through the tunnel is exactly the
/// one that must not open them.
pub fn is_operator_path(method: &Method, path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let post = *method == Method::POST;
    let get = *method == Method::GET;
    let delete = *method == Method::DELETE;
    match parts.as_slice() {
        ["api", "principals"] => post,
        ["api", "principals", _, "state"] => post,
        ["api", "principals", _, "quota"] => post || delete,
        ["api", "grants"] => post,
        ["api", "waitlist"] => get,
        ["api", "waitlist", _] => delete,
        ["api", "invitations"] => post,
        ["api", "reports"] => get,
        ["api", "reports", _, "dismiss"] => post,
        ["api", "repos", _, _, "mirror"] | ["api", "repos", _, _, "import"] => post,
        ["api", "principals", _, "workload"] => post,
        ["people"] | ["teams"] | ["reports"] => get || post,
        [_, _, "settings", "mirror"] => post,
        _ => false,
    }
}

/// The public listener's refusal of the operator's door, when that door
/// is elsewhere: answered as a route that is not here, in the shape the
/// caller reads.
pub async fn operator_surface(
    axum::extract::State(app): axum::extract::State<crate::AppState>,
    request: Request,
    next: Next,
) -> Response {
    if app.operator_elsewhere() && is_operator_path(request.method(), request.uri().path()) {
        let path = request.uri().path();
        if path.starts_with("/api/") {
            return crate::error::ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "no such route here: this forge serves its operator's door on another listener",
            )
            .into_response();
        }
        return (
            StatusCode::NOT_FOUND,
            [(
                axum::http::HeaderName::from_static(crate::web::FALLBACK),
                "not-found",
            )],
            "",
        )
            .into_response();
    }
    next.run(request).await
}

/// What a reader is allowed, before being told to wait.
///
/// Writes have had an allowance since agents started retrying them;
/// reads had none, and reads are what a stranger can ask for without
/// an account. A clone is the expensive one: it forks git and streams
/// a pack, and nothing about being anonymous made it cheaper.
///
/// Whoever is asking decides whose allowance is spent — a principal
/// when the request carries identity, the source address otherwise —
/// so one busy agent cannot use up what everybody else has, and a
/// stranger cannot use up what people with accounts have. Assets and
/// the health check are not counted: they are cheap, and a monitor
/// polling `/healthz` should never be the thing that runs out.
pub async fn read_allowance(
    axum::extract::State(app): axum::extract::State<crate::AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    if path.starts_with("/assets/") {
        return next.run(request).await;
    }
    // The health check is what a monitor polls, so it must not run out
    // with everything else — but it takes the store lock, and a free
    // path to the lock is a door. It has an allowance of its own,
    // generous for any monitor and closed to a loop.
    if path == "/healthz" {
        return match app.health_limiter.check(caller_address(&app, &request)) {
            Ok(()) => next.run(request).await,
            Err(wait) => rate_limited_read(wait),
        };
    }
    // Every request costs something. Writes under /api/ have their own
    // allowance and are not charged twice; everything else — a page, an
    // advertisement, a form, a method nobody routes — spends here, so
    // no door reaches the store lock for free. A clone is two requests:
    // an advertisement, which is a GET, and the pack itself, which is a
    // POST, and the pack is the part that forks git.
    let pack = path.starts_with("/git/") && method == Method::POST;
    let api_write = path.starts_with("/api/") && !matches!(method, Method::GET | Method::HEAD);
    if api_write {
        return next.run(request).await;
    }
    let cost = if pack { PACK_COSTS } else { 1 };
    let json = path.starts_with("/api/") || path.starts_with("/git/");
    let refused = match crate::web::requester(&app, &path, request.headers()) {
        Some(who) => app.read_limiter.spend(who, cost).err(),
        None => {
            // The address is always charged: a caller who can invent a
            // fresh identity per request must not be able to invent a
            // fresh allowance with it. A credential that was offered and
            // did not resolve — revoked, expired, deactivated — is charged
            // a small allowance of its own on top, so a loop on a dead
            // token is told to stop sooner and does not spend what every
            // visitor from the same place has.
            let address = caller_address(&app, &request);
            let over_address = app.anonymous_read_limiter.spend(address, cost).err();
            let over_credential = offered_credential(&request)
                .and_then(|hash| app.bad_credential_limiter.check(hash).err());
            over_address.or(over_credential)
        }
    };
    match refused {
        Some(wait) if json => rate_limited_read(wait),
        // Marked for the theme pass, so a person sees a page in their
        // theme rather than a line of text.
        Some(wait) => (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (
                    header::RETRY_AFTER,
                    wait.as_secs_f64().ceil().max(1.0).to_string(),
                ),
                (
                    axum::http::HeaderName::from_static("x-cairn-fallback"),
                    "too-many".to_owned(),
                ),
            ],
            "Too many requests. Wait a moment and try again.",
        )
            .into_response(),
        None => next.run(request).await,
    }
}

/// Whether the missing-address warning has been given.
static NO_ADDRESS_SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Whether the short-header warning has been given.
static SHORT_FORWARDED_SAID: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// How many units a pack transfer spends. A clone forks git and streams
/// history; a page load does not.
const PACK_COSTS: u32 = 20;

/// The address a request came from, as one caller. Never absent: a
/// request with no peer address — an embedding that serves without
/// connection information — shares one bucket rather than escaping
/// every bucket, and the first such request says so in the log.
pub(crate) fn caller_address(app: &crate::AppState, request: &Request) -> IpAddr {
    match client_ip(app, request) {
        Some(address) => address,
        None => {
            if !NO_ADDRESS_SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "a request arrived with no peer address; every such request shares one allowance"
                );
            }
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        }
    }
}

/// A fingerprint of whatever credential was offered, for the extra
/// allowance a dead credential spends. Not a bucket in its own right —
/// see `read_allowance` — because a fresh header per request would
/// otherwise be a fresh allowance per request.
fn offered_credential(request: &Request) -> Option<String> {
    let offered = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let mut hasher = Sha256::new();
    hasher.update(offered.as_bytes());
    Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// The caller's address, read off a whole request rather than its
/// parts, for middleware that has not taken it apart yet.
fn client_ip(app: &crate::AppState, request: &Request) -> Option<IpAddr> {
    resolve_address(
        app.proxy_trust(),
        request.headers(),
        request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|connected| connected.0.ip()),
    )
}

/// One rule for every place that asks who is connecting, so a limiter
/// keyed by the extractor and one keyed by the middleware agree.
fn resolve_address(
    trust: ProxyTrust,
    headers: &axum::http::HeaderMap,
    connected: Option<IpAddr>,
) -> Option<IpAddr> {
    let address = match trust {
        ProxyTrust::ForwardedHeader { hops } => match forwarded(headers, hops) {
            Some(address) => Some(address),
            None => {
                // Fewer hops than the operator said. Believing the header
                // here would mean believing an entry a client wrote, so
                // the connection is taken instead — which behind a proxy
                // is the proxy, and everybody shares it. Said once, so
                // the misconfiguration is findable.
                if headers.contains_key("x-forwarded-for")
                    && !SHORT_FORWARDED_SAID.swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::warn!(
                        hops,
                        "X-Forwarded-For had fewer entries than --proxy-hops; keying on the connection"
                    );
                }
                connected
            }
        },
        ProxyTrust::Connection => connected,
    };
    address.map(as_one_caller)
}

/// The part of an address that is one caller. A home gets a whole IPv6
/// /64, so keying on the full address hands every host in it — and an
/// attacker rotating through 2^64 of them — a fresh allowance each.
fn as_one_caller(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        // A v4 client on a dual-stack socket arrives as ::ffff:a.b.c.d,
        // whose top 64 bits are all zero; grouping it by /64 would put
        // the whole IPv4 internet in one bucket. It is a v4 address.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
        },
    }
}

/// A token bucket per caller: a source address for the forms a stranger
/// can post to, a principal for API traffic. Each caller holds up to
/// `allowed` units and earns them back evenly over `window`, so a
/// burst is bounded at every moment rather than only within a fixed
/// window — the fixed kind lets twice the allowance through in the
/// second that straddles a boundary. Deliberately small: it exists to
/// make guessing and runaway loops pointless, not to shape traffic.
#[derive(Clone)]
pub struct Limiter<K: Eq + Hash> {
    attempts: Arc<Mutex<Buckets<K>>>,
    allowed: u32,
    window: Duration,
}

/// Per caller: units spent that have not yet been earned back, and when
/// that was last brought up to date; and when the map was last swept.
struct Buckets<K> {
    attempts: HashMap<K, (f64, Instant)>,
    swept: Instant,
}

/// How many callers one limiter remembers at once. A window's worth of
/// distinct addresses is normally far fewer; this is the ceiling that
/// keeps a flood of them from becoming this process's memory.
const MOST_CALLERS: usize = 50_000;

/// How many may accumulate before the map is swept at all.
const SWEEP_AT: usize = 1024;

/// Sign-in and the other public forms are keyed by source address.
pub type LoginLimiter = Limiter<IpAddr>;

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(60))
    }
}

impl<K: Eq + Hash> Limiter<K> {
    pub fn new(allowed: u32, window: Duration) -> Self {
        Limiter {
            attempts: Arc::new(Mutex::new(Buckets {
                attempts: HashMap::new(),
                swept: Instant::now(),
            })),
            allowed,
            window,
        }
    }

    /// A limiter that refuses nobody, for an operator who has turned
    /// the allowance off.
    pub fn unlimited() -> Self {
        Self::new(u32::MAX, Duration::from_secs(60))
    }

    /// Record an attempt; false means this caller has had enough.
    pub fn accept(&self, from: K) -> bool {
        self.check(from).is_ok()
    }

    /// Record an attempt. A refusal says how long until this caller's
    /// window opens again, which is what `Retry-After` tells them.
    pub fn check(&self, from: K) -> Result<(), Duration> {
        self.spend(from, 1)
    }

    /// Record work worth `cost` units. A refusal says how long until
    /// enough has been earned back for this much, which is what
    /// `Retry-After` tells the caller.
    pub fn spend(&self, from: K, cost: u32) -> Result<(), Duration> {
        if self.allowed == u32::MAX {
            return Ok(());
        }
        if self.allowed == 0 {
            // Nothing is ever earned back, so nothing is ever allowed;
            // the arithmetic below would divide by that.
            return Err(self.window);
        }
        let mut state = match self.attempts.lock() {
            Ok(state) => state,
            // A poisoned lock must not lock everyone out.
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let per_second = f64::from(self.allowed) / self.window.as_secs_f64().max(f64::EPSILON);
        // Sweeping the whole map is work proportional to how many callers
        // there are, done while holding the lock every other request is
        // waiting on. So it happens on a clock, not per request: at most
        // once a second, dropping callers whose debt has drained. If a
        // flood of distinct callers still fills it, newcomers wait
        // rather than the map growing without end — under that kind of
        // load, a stranger waiting is the right outcome.
        if state.attempts.len() >= SWEEP_AT
            && now.duration_since(state.swept) >= Duration::from_secs(1)
        {
            state.swept = now;
            state.attempts.retain(|_, (spent, at)| {
                *spent - now.duration_since(*at).as_secs_f64() * per_second > 0.0
            });
        }
        if state.attempts.len() >= MOST_CALLERS && !state.attempts.contains_key(&from) {
            return Err(Duration::from_secs(1));
        }
        let allowed = f64::from(self.allowed);
        let (spent, at) = state.attempts.entry(from).or_insert((0.0, now));
        // Earn back what the time since the last visit is worth.
        *spent = (*spent - now.duration_since(*at).as_secs_f64() * per_second).max(0.0);
        *at = now;
        let asking = f64::from(cost);
        // A single unit of work larger than the whole allowance cannot
        // be metered, only rationed: it is served when the bucket is
        // empty, and refused until it is.
        if asking > allowed {
            return if *spent <= 0.0 {
                *spent = allowed;
                Ok(())
            } else {
                Err(Duration::from_secs_f64((*spent / per_second).max(0.001)))
            };
        }
        if *spent + asking <= allowed {
            *spent += asking;
            Ok(())
        } else {
            // The refusal is not charged: a caller told to wait is not
            // made to wait longer for having asked.
            let short = *spent + asking - allowed;
            Err(Duration::from_secs_f64((short / per_second).max(0.001)))
        }
    }
}

/// The caller's address. In-process callers (tests, embedded use)
/// have none, and share one bucket under the unspecified address:
/// an allowance that a request with no address escapes is an
/// allowance that any request can escape.
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
    /// The address recorded in X-Forwarded-For by the trusted proxies,
    /// `hops` of them deep: one means the nearest proxy's own client,
    /// which is the only entry a client cannot forge.
    ForwardedHeader { hops: u8 },
}

/// Read the address a trusted proxy recorded. The rightmost entry is
/// the one the nearest proxy added; entries further left were supplied
/// by whatever came before it, including the client.
/// The address a trusted proxy recorded. Each proxy appends the address
/// it received from, so the rightmost entry is the nearest proxy's
/// client; behind two proxies the nearest proxy's client is the far
/// proxy, and the visitor is one hop further left. Nothing left of the
/// trusted hops is believed, because a client writes that part itself.
fn forwarded(headers: &axum::http::HeaderMap, hops: u8) -> Option<IpAddr> {
    let hops = hops.max(1);
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .rsplit(',')
        .map(str::trim)
        .nth(usize::from(hops) - 1)
        .and_then(|hop| hop.parse().ok())
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
        Ok(ClientIp(resolve_address(
            state.proxy_trust(),
            &parts.headers,
            connected,
        )))
    }
}

pub fn too_many_attempts() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, "60"),
            // A form's refusal is read in a browser, and gets the page.
            (
                axum::http::HeaderName::from_static(crate::web::FALLBACK),
                "too-many",
            ),
        ],
        "Too many sign-in attempts. Wait a minute and try again.",
    )
        .into_response()
}

/// The same, for a read: a caller that cannot tell these apart would
/// wait either way, and one that can knows which of its loops to slow.
pub fn rate_limited_read(wait: Duration) -> Response {
    let seconds = wait.as_secs_f64().ceil().max(1.0) as u64;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, seconds.to_string())],
        axum::Json(serde_json::json!({
            "kind": "rate_limited",
            "error": format!("too many reads; wait {seconds}s and try again"),
            "detail": { "retry_after": seconds },
        })),
    )
        .into_response()
}

/// The API's refusal: typed like every other API error, with the wait
/// stated twice - in the header a client library reads, and in the body
/// an agent does.
pub fn rate_limited(wait: Duration) -> Response {
    let seconds = wait.as_secs_f64().ceil().max(1.0) as u64;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, seconds.to_string())],
        axum::Json(serde_json::json!({
            "kind": "rate_limited",
            "error": format!("too many writes; wait {seconds}s and try again"),
            "detail": { "retry_after": seconds },
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operators_door_is_a_known_list() {
        for (method, path) in [
            (Method::POST, "/api/principals"),
            (Method::POST, "/api/grants"),
            (Method::POST, "/api/principals/ada/state"),
            (Method::DELETE, "/api/principals/ada/quota"),
            (Method::GET, "/api/waitlist"),
            (Method::DELETE, "/api/waitlist/a%40b.c"),
            (Method::POST, "/api/invitations"),
            (Method::GET, "/api/reports"),
            (Method::POST, "/api/reports/3/dismiss"),
            (Method::POST, "/api/repos/ada/demo/mirror"),
            (Method::POST, "/api/repos/ada/demo/import"),
            (Method::POST, "/api/principals/scout/workload"),
            (Method::GET, "/people"),
            (Method::POST, "/teams"),
            (Method::GET, "/reports"),
            (Method::POST, "/reports"),
            (Method::POST, "/ada/demo/settings/mirror"),
        ] {
            assert!(is_operator_path(&method, path), "{method} {path}");
        }
        for (method, path) in [
            (Method::GET, "/api/principals/ada"),
            (Method::GET, "/api/principals/ada/quota"),
            (Method::GET, "/api/grants?grantee=scout"),
            (Method::POST, "/api/grants/g-1/revoke"),
            (Method::POST, "/api/principals/ada/tokens"),
            (Method::GET, "/api/repos/ada/demo/mirror"),
            (Method::GET, "/api/teams/crew/members"),
            (Method::POST, "/api/teams/crew/members"),
            (Method::POST, "/api/teams/crew/members/remove"),
            (Method::POST, "/waitlist"),
            (Method::POST, "/report"),
            (Method::GET, "/you"),
        ] {
            assert!(!is_operator_path(&method, path), "{method} {path}");
        }
    }

    /// A fixed window lets twice the allowance through in the second
    /// that straddles a boundary. A bucket does not: what was spent is
    /// earned back evenly, so a full burst is followed by a wait.
    #[test]
    fn a_burst_is_followed_by_a_wait_not_a_second_burst() {
        let limiter: Limiter<&str> = Limiter::new(10, Duration::from_secs(10));
        for _ in 0..10 {
            assert!(limiter.check("a").is_ok());
        }
        let wait = limiter.check("a").expect_err("the eleventh waits");
        // One unit is earned back per second, so the wait is about that.
        assert!(wait <= Duration::from_secs(1), "{wait:?}");
        assert!(wait > Duration::from_millis(500), "{wait:?}");
        // A refusal is not charged: asking again does not lengthen it.
        let again = limiter.check("a").expect_err("still waiting");
        assert!(again <= wait, "{again:?} > {wait:?}");
        // Somebody else is unaffected.
        assert!(limiter.check("b").is_ok());
    }

    #[test]
    fn a_pack_spends_more_than_a_page() {
        let limiter: Limiter<&str> = Limiter::new(25, Duration::from_secs(60));
        assert!(limiter.spend("a", 20).is_ok());
        assert!(
            limiter.spend("a", 20).is_err(),
            "two packs are more than the allowance"
        );
        assert!(
            limiter.check("a").is_ok(),
            "a page still fits in what is left"
        );
    }

    /// A single unit of work larger than the whole allowance cannot be
    /// metered, only rationed: served on an empty bucket, refused until
    /// it drains, never refused forever with a wait that lies.
    #[test]
    fn a_unit_larger_than_the_allowance_is_rationed_not_refused_forever() {
        let limiter: Limiter<&str> = Limiter::new(10, Duration::from_secs(10));
        assert!(
            limiter.spend("a", 20).is_ok(),
            "an empty bucket serves it once"
        );
        let wait = limiter.spend("a", 20).expect_err("and then it waits");
        assert!(wait <= Duration::from_secs(10), "{wait:?}");
        assert!(limiter.check("a").is_err(), "the bucket is full meanwhile");
    }

    /// An allowance of nothing must not divide by nothing.
    #[test]
    fn an_allowance_of_zero_refuses_without_panicking() {
        let limiter: Limiter<&str> = Limiter::new(0, Duration::from_secs(10));
        assert!(limiter.check("a").is_err());
        assert!(limiter.spend("a", 5).is_err());
    }

    /// A v4 client on a dual-stack socket arrives as ::ffff:a.b.c.d. Its
    /// top 64 bits are zero, and grouping it by /64 would put the whole
    /// IPv4 internet in one bucket.
    #[test]
    fn a_mapped_v4_address_is_its_own_v4_address() {
        let mapped: IpAddr = "::ffff:203.0.113.4".parse().unwrap();
        let other: IpAddr = "::ffff:198.51.100.9".parse().unwrap();
        assert_ne!(as_one_caller(mapped), as_one_caller(other));
        assert_eq!(
            as_one_caller(mapped),
            "203.0.113.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn an_address_is_its_home_on_v6() {
        let one: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let other: IpAddr = "2001:db8:1:2:1111:2222:3333:4444".parse().unwrap();
        let elsewhere: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(as_one_caller(one), as_one_caller(other));
        assert_ne!(as_one_caller(one), as_one_caller(elsewhere));
        let v4: IpAddr = "203.0.113.4".parse().unwrap();
        assert_eq!(as_one_caller(v4), v4);
    }

    #[test]
    fn the_visitor_is_as_many_hops_from_the_right_as_there_are_proxies() {
        let request = axum::http::Request::builder()
            .header("x-forwarded-for", "10.0.0.1, 198.51.100.9, 203.0.113.4")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        assert_eq!(
            forwarded(&parts.headers, 2),
            Some("198.51.100.9".parse().unwrap()),
            "behind a CDN and a proxy, the visitor is two from the right"
        );
        assert_eq!(
            forwarded(&parts.headers, 9),
            None,
            "past the list is nobody"
        );
    }

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
            forwarded(&parts.headers, 1),
            Some("203.0.113.4".parse().unwrap()),
            "the rightmost hop is the one a client cannot forge"
        );

        let empty = axum::http::Request::builder().body(()).unwrap();
        let (parts, ()) = empty.into_parts();
        assert_eq!(forwarded(&parts.headers, 1), None);
    }

    #[test]
    fn a_caller_gets_its_allowance_and_no_more() {
        let limiter = LoginLimiter::new(3, Duration::from_secs(60));
        let caller: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.accept(caller));
        assert!(limiter.accept(caller));
        assert!(limiter.accept(caller));
        let wait = limiter
            .check(caller)
            .expect_err("the fourth attempt is refused");
        // A bucket earns one attempt back every window/allowed: twenty
        // seconds here. The wait names that, not the rest of a minute.
        assert!(
            wait > Duration::from_secs(15) && wait <= Duration::from_secs(20),
            "the refusal says how long until the next attempt is earned: {wait:?}"
        );
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
