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
}

/// Boot a forge with git hosting, principals (human `ada`, agents
/// `scout` and `arbiter` of distinct models), and a repo `demo`.
pub async fn boot() -> Forge {
    boot_with("sha1").await
}

pub async fn boot_with(object_format: &str) -> Forge {
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
    let (_, scout_token, _) = store.mint_token(&scout, &scout, Some("test")).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let git_store = GitStore::new(&repos, env!("CARGO_BIN_EXE_cairn"));
    let state = AppState::new(store)
        .with_dev_identity()
        .with_git(git_store, format!("http://{addr}"));
    cairn_server::spawn_queue_processor(state.clone());
    let app = router(state);
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    let (status, _) = api(
        &app,
        "POST",
        "/api/repos",
        "ada",
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
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Ada")
        .env("GIT_AUTHOR_EMAIL", "ada@example.test")
        .env("GIT_COMMITTER_NAME", "Ada")
        .env("GIT_COMMITTER_EMAIL", "ada@example.test")
        .args(args)
        .output()
        .expect("run git")
}

pub async fn api(
    app: &Router,
    method: &str,
    path: &str,
    actor: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-cairn-principal", actor);
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
        serde_json::from_slice(&bytes).unwrap()
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
    std::fs::write(wc.join(file), contents).unwrap();
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
