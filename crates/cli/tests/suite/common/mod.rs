//! Shared harness for the end-to-end suites: a booted forge with git
//! hosting, principals, grants, a token, and the landing processor —
//! plus git and HTTP helpers.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use cairn_core::{PrincipalId, PrincipalKind, Store};
use cairn_git::GitStore;
use cairn_server::{AppState, router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tower::ServiceExt;

pub struct Forge {
    pub _tmp: tempfile::TempDir,
    pub app: Router,
    pub addr: SocketAddr,
    pub work: PathBuf,
    pub scout_token: String,
    /// A human's token, for the flows that must be driven by real
    /// credentials rather than the dev header.
    pub ada_token: String,
    /// Kept so tests can reach the store directly, e.g. to check that
    /// the log still explains every projection after a real flow.
    pub state: AppState,
}

/// Boot a forge with git hosting, principals (human `ada`, agents
/// `scout` and `arbiter` of distinct models), and a repo `demo`.
pub async fn boot() -> Forge {
    boot_with("sha1").await
}

pub async fn boot_with(object_format: &str) -> Forge {
    boot_inner(object_format, true, None).await
}

/// A forge that knows its public URL, so passkeys are on.
pub async fn boot_with_passkeys() -> Forge {
    let mut forge = boot_inner("sha1", true, None).await;
    let state = forge
        .state
        .clone()
        .with_public_url("https://forge.example")
        .expect("a valid public URL");
    forge.app = router(state.clone());
    forge.state = state;
    forge
}

/// A forge with a public URL that signs people in with `provider` and
/// trusts it for workloads too.
pub async fn boot_with_oidc(provider: cairn_server::oidc::Provider) -> Forge {
    let mut forge = boot_inner("sha1", true, None).await;
    let issuer = provider.issuer.clone();
    let state = forge
        .state
        .clone()
        .with_public_url("https://forge.example")
        .expect("a valid public URL")
        .with_oidc(cairn_server::oidc::Trust::new(
            Some(provider),
            vec![issuer],
            None,
        ));
    forge.app = router(state.clone());
    forge.state = state;
    forge
}

/// A forge that can send mail and knows its public URL - a deployment.
pub async fn boot_mailing_public(command: &str) -> Forge {
    let mut forge = boot_inner(
        "sha1",
        true,
        Some(cairn_server::Mailer::command(
            command,
            "cairn@forge.example",
        )),
    )
    .await;
    let state = forge
        .state
        .clone()
        .with_public_url("https://forge.example")
        .expect("a valid public URL");
    forge.app = router(state.clone());
    forge.state = state;
    forge
}

/// A forge that can send mail, through a command of the test's choosing.
pub async fn boot_mailing(command: &str) -> Forge {
    boot_inner(
        "sha1",
        true,
        Some(cairn_server::Mailer::command(
            command,
            "cairn@forge.example",
        )),
    )
    .await
}

/// A forge with the dev identity header switched off — how a real
/// deployment runs, where identity comes only from a token. Anything
/// asserting something about authentication has to use this, because the
/// dev header bypasses tokens entirely.
pub async fn boot_token_only() -> Forge {
    boot_inner("sha1", false, None).await
}

async fn boot_inner(object_format: &str, dev: bool, mailer: Option<cairn_server::Mailer>) -> Forge {
    boot_core(object_format, dev, mailer, false).await
}

/// Like `boot`, but the landing train spends attention budgets on its
/// own tick, as in production.
pub async fn boot_drawing() -> Forge {
    boot_core("sha1", true, None, true).await
}

async fn boot_core(
    object_format: &str,
    dev: bool,
    mailer: Option<cairn_server::Mailer>,
    draws: bool,
) -> Forge {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    let ada = PrincipalId::new("ada").unwrap();
    let scout = PrincipalId::new("scout").unwrap();
    let arbiter = PrincipalId::new("arbiter").unwrap();
    store
        .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
        .unwrap();
    // Ada runs this forge. Nobody is sovereign for being human any more,
    // so somebody has to hold the grant that running it consists of —
    // exactly as `cairn admin bootstrap` arranges in production.
    store.grant_bootstrap_admin(&ada).unwrap();
    store
        .register_principal(
            &ada,
            &scout,
            PrincipalKind::Agent,
            "Scout",
            Some("claude-fable-5"),
            None,
        )
        .unwrap();
    store
        .register_principal(
            &ada,
            &arbiter,
            PrincipalKind::Agent,
            "Arbiter",
            Some("gpt-6"),
            None,
        )
        .unwrap();
    store
        .issue_grant(
            &ada,
            &scout,
            None,
            vec![cairn_core::Capability::Task, cairn_core::Capability::Push],
            None,
        )
        .unwrap();
    let (_, scout_token, _) = store
        .mint_token(&scout, &scout, Some("test"), None)
        .unwrap();
    let (_, ada_token, _) = store.mint_token(&ada, &ada, Some("test"), None).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let git_store = GitStore::new(&repos, env!("CARGO_BIN_EXE_cairn"));
    let mut state = AppState::new(store).with_git(git_store, format!("http://{addr}"));
    if !draws {
        state = state.without_automatic_draws();
    }
    if dev {
        state = state.with_dev_identity();
    }
    if let Some(mailer) = mailer {
        state = state.with_mailer(mailer);
    }
    cairn_server::spawn_queue_processor(state.clone());
    let app = router(state.clone());
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // Authenticate the setup with a real token rather than the dev
    // header, so booting works the same whether or not dev identity is on.
    let (status, _) = api_with_token(
        &app,
        "POST",
        "/api/repos",
        &ada_token,
        Some(json!({ "name": "demo", "object_format": object_format })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(repos.join("demo.git").is_dir());

    Forge {
        _tmp: tmp,
        app,
        addr,
        work,
        scout_token,
        ada_token,
        state,
    }
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let output = git_raw(dir, args);
    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Run git expecting failure; returns combined output for assertions.
pub fn git_expect_fail(dir: &Path, args: &[&str]) -> String {
    let output = git_raw(dir, args);
    assert!(
        !output.status.success(),
        "git {args:?} unexpectedly succeeded"
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn git_raw(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(dir)
        // Hermetic on purpose. Whatever git configuration the machine
        // carries must not reach these tests: an inherited credential
        // helper can satisfy a push the test expects to be *refused*,
        // which makes the suite's answer depend on what happens to be
        // cached in a keychain. Signing, autocrlf and a default branch
        // name would all leak in the same way.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Ada")
        .env("GIT_AUTHOR_EMAIL", "ada@example.test")
        .env("GIT_COMMITTER_NAME", "Ada")
        .env("GIT_COMMITTER_EMAIL", "ada@example.test")
        .args(args)
        .output()
        .expect("run git")
}

/// Make a request authenticated the way the outside world must:
/// a bearer token, with no dev header anywhere.
/// A request with no identity at all: what a stranger's browser or a
/// script without a token sends.
pub async fn api_anonymous(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder().method(method).uri(path);
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

pub async fn api_with_token(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    request_with(
        app,
        method,
        path,
        ("authorization", format!("Bearer {token}")),
        body,
    )
    .await
}

/// Give a principal a password, sign in, and hand back the session
/// cookie — the shape most account tests need before they can start.
pub async fn sign_in_as(forge: &Forge, who: &str) -> (StatusCode, String) {
    const PASSWORD: &str = "a perfectly ordinary password";
    api_with_token(
        &forge.app,
        "POST",
        &format!("/api/principals/{who}/password"),
        &forge.ada_token,
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    let (status, cookie) = sign_in(&forge.app, who, PASSWORD).await;
    let cookie = cookie
        .expect("signing in should set a session")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (status, cookie)
}

/// Post the sign-in form. Returns the status and the Set-Cookie header,
/// which is what actually matters about a successful sign-in.
pub async fn sign_in(
    app: &Router,
    principal: &str,
    password: &str,
) -> (StatusCode, Option<String>) {
    let body = format!(
        "principal={}&password={}",
        urlencode(principal),
        urlencode(password)
    );
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("cairn_session="))
        .map(str::to_owned);
    (status, cookie)
}

/// Where a failed sign-in sends you, which is the whole message a
/// visitor gets and therefore the thing that must not vary by account.
pub async fn redirect_of(app: &Router, principal: &str, password: &str) -> String {
    let body = format!(
        "principal={}&password={}",
        urlencode(principal),
        urlencode(password)
    );
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_owned(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Fetch a page carrying a raw Cookie header, for asserting what the
/// browser half does with a credential. Returns the status only: these
/// callers care whether they were let in, not what was rendered.
pub async fn get_with_cookie(app: &Router, path: &str, cookie: &str) -> StatusCode {
    page_with_cookie(app, path, cookie).await.0
}

/// The same, keeping the rendered body — for asserting that something
/// hostile produced no content it should not have.
pub async fn page_with_cookie(app: &Router, path: &str, cookie: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn api(
    app: &Router,
    method: &str,
    path: &str,
    actor: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    request_with(
        app,
        method,
        path,
        ("x-cairn-principal", actor.to_owned()),
        body,
    )
    .await
}

async fn request_with(
    app: &Router,
    method: &str,
    path: &str,
    (header, value): (&str, String),
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header, value);
    let request = match body {
        Some(json) => request
            .header("content-type", "application/json")
            .body(Body::from(json.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        // A non-JSON body is nearly always a route that did not match or
        // a rejected extractor, and the body says which. Swallowing it
        // turns a one-line diagnosis into a hunt.
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "{method} {path} returned {status} with a body that is not JSON ({e}): {}",
                String::from_utf8_lossy(&bytes)
            )
        })
    };
    (status, value)
}

/// Satisfy default policy for a change and merge it: passing test claim
/// from the agent, human approval, merge as the human.
pub async fn approve_and_merge(app: &Router, change_id: &str) -> Value {
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true,
            "summary": "verified", "command": "cargo test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/verdicts"),
        "ada",
        Some(json!({
            "domain": "correctness", "disposition": "approve",
            "rationale": "Reviewed and correct."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, merged) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "merge failed: {merged}");
    merged
}

/// Make a change ready and hand it to the landing train, which is the
/// path that rebases when the target has moved.
pub async fn approve_and_enqueue(app: &Router, change_id: &str) {
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/claims"),
        "scout",
        Some(json!({ "kind": "test", "passed": true, "summary": "verified" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/verdicts"),
        "ada",
        Some(json!({
            "domain": "correctness", "disposition": "approve",
            "rationale": "Reviewed and correct."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/enqueue"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enqueue failed: {body}");
}

pub fn commit_file(wc: &Path, file: &str, contents: &str, message: &str) {
    let path = wc.join(file);
    // Nested paths are the interesting ones for leases and blame, so
    // they should not need a separate mkdir at every call site.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, contents).unwrap();
    git(wc, &["add", "."]);
    git(wc, &["commit", "-m", message]);
}

/// Poll the API until a condition holds; panic with context on timeout.
pub async fn wait_for<F>(app: &Router, what: &str, mut check: F)
where
    F: AsyncFnMut(&Router) -> bool,
{
    for _ in 0..100 {
        if check(app).await {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Submit a form as a signed-in browser would, and report where it was
/// sent next. Pages answer a form with a redirect, so the location is
/// the interesting part of the response.
pub async fn post_form(app: &Router, path: &str, cookie: &str, body: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", cookie)
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, location)
}

/// GET a path as a signed-in browser and report where it was sent.
/// Like `get_redirect`, and also hand back the `set-cookie` header the
/// response carried, for flows that sign a browser in on the way.
pub async fn get_redirect_with_cookie(
    app: &Router,
    path: &str,
    cookie: &str,
) -> (StatusCode, String, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (status, location, set_cookie)
}

pub async fn get_redirect(app: &Router, path: &str, cookie: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, location)
}

/// Follow a redirect that carries a spent-once flash and return what the
/// page showed inside `<code class="secret">`. The secret must not be in
/// the URL itself; that is the whole point of the flash.
pub async fn shown_once(app: &Router, location: &str, cookie: &str) -> String {
    assert!(
        location.contains("?once=")
            && !location.contains("secret=")
            && !location.contains("invite="),
        "the redirect carries an id, never the secret: {location}"
    );
    let (status, page) = page_with_cookie(app, location, cookie).await;
    assert_eq!(status, StatusCode::OK);
    let start = page
        .find(r#"<code class="secret">"#)
        .expect("something shown once")
        + r#"<code class="secret">"#.len();
    let end = page[start..].find("</code>").unwrap() + start;
    page[start..end].to_owned()
}
