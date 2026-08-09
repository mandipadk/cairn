//! The transport end to end: real git client, real receive-pack, the
//! real hook binary, and the graph — clone, push to refs/for/main,
//! amend into a second revision, review, merge under policy, and watch
//! refs/heads/main advance on the wire.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use cairn_core::{PrincipalId, PrincipalKind, Store};
use cairn_git::GitStore;
use cairn_server::{AppState, router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use tower::ServiceExt;

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Ada")
        .env("GIT_AUTHOR_EMAIL", "ada@example.test")
        .env("GIT_COMMITTER_NAME", "Ada")
        .env("GIT_COMMITTER_EMAIL", "ada@example.test")
        .args(args)
        .output()
        .expect("run git");
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

async fn api(
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

#[tokio::test(flavor = "multi_thread")]
async fn push_review_merge_over_real_git() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    // Forge with a human and two agents of distinct models.
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let git_store = GitStore::new(&repos, env!("CARGO_BIN_EXE_cairn"));
    let app = router(AppState::new(store).with_git(git_store, format!("http://{addr}")));
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // Creating the repo over the API also creates the bare repo on disk.
    let (status, _) = api(
        &app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(repos.join("demo.git").is_dir());

    // Clone (anonymous reads), commit with a Change-Id trailer.
    git(&work, &["clone", &format!("http://{addr}/git/demo"), "wc"]);
    let wc = work.join("wc");
    std::fs::write(wc.join("greeting.txt"), "hello\n").unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &["commit", "-m", "Add greeting\n\nChange-Id: If00dcafe01"],
    );
    let first_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();

    // Anonymous pushes are refused before touching receive-pack.
    let denied = Command::new("git")
        .current_dir(&wc)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["push", "origin", "HEAD:refs/for/main"])
        .output()
        .unwrap();
    assert!(!denied.status.success(), "anonymous push must fail");

    // The transport IS the API: push to refs/for/main creates a change.
    let push_url = format!("http://scout:x@{addr}/git/demo");
    git(&wc, &["remote", "set-url", "origin", &push_url]);
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (status, changes) = api(&app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changes.as_array().unwrap().len(), 1);
    let change = &changes[0];
    assert_eq!(change["number"], 1);
    assert_eq!(change["title"], "Add greeting");
    assert_eq!(change["owner"], "scout");
    assert_eq!(change["external_key"], "If00dcafe01");
    assert_eq!(change["latest_revision"], 1);
    let change_id = change["id"].as_str().unwrap().to_owned();

    // The revision ref exists on the wire and matches the pushed commit.
    let refs = git(&wc, &["ls-remote", "origin"]);
    assert!(
        refs.contains("refs/changes/1/1"),
        "missing change ref:\n{refs}"
    );
    assert!(
        refs.lines()
            .any(|l| l.starts_with(&first_oid) && l.contains("refs/changes/1/1"))
    );

    // Amend (same Change-Id) and push again: revision 2 of the SAME change.
    std::fs::write(wc.join("greeting.txt"), "hello, forge\n").unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &[
            "commit",
            "--amend",
            "-m",
            "Add greeting\n\nChange-Id: If00dcafe01",
        ],
    );
    let second_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (_, changes) = api(&app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(
        changes.as_array().unwrap().len(),
        1,
        "amend must not open a second change"
    );
    assert_eq!(changes[0]["latest_revision"], 2);

    // Every revision stays fetchable by its stable ref.
    git(&wc, &["fetch", "origin", "refs/changes/1/1"]);
    assert_eq!(git(&wc, &["rev-parse", "FETCH_HEAD"]).trim(), first_oid);

    // Merge is refused until policy is satisfied — then verification,
    // independent judgment, and the merge moves the real branch.
    let (status, refusal) = api(
        &app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "scout",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal["kind"], "policy_unsatisfied");

    let (status, _) = api(
        &app,
        "POST",
        &format!("/api/changes/{change_id}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true,
            "summary": "greeting rendered as expected",
            "command": "cat greeting.txt",
            "unchecked": ["non-ascii greetings"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        &app,
        "POST",
        &format!("/api/changes/{change_id}/verdicts"),
        "ada",
        Some(json!({
            "domain": "correctness", "disposition": "approve",
            "rationale": "Exactly the greeting we wanted."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, merged) = api(
        &app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "merge failed: {merged}");
    assert_eq!(merged["event"]["kind"], "change_merged");
    assert_eq!(merged["event"]["revision"], 2);

    // The branch advanced to the merged revision, visible to any client.
    let main_ref = git(&wc, &["ls-remote", "origin", "refs/heads/main"]);
    assert!(
        main_ref.starts_with(&second_oid),
        "main should point at revision 2 ({second_oid}); got:\n{main_ref}"
    );
    git(&wc, &["fetch", "origin", "main"]);
    assert_eq!(git(&wc, &["rev-parse", "FETCH_HEAD"]).trim(), second_oid);

    // A fresh clone sees the merged history — the loop is closed.
    git(
        &work,
        &["clone", &format!("http://{addr}/git/demo"), "verify"],
    );
    let contents = std::fs::read_to_string(work.join("verify/greeting.txt")).unwrap();
    assert_eq!(contents, "hello, forge\n");
}
