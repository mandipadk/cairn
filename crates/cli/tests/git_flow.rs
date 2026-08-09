//! The transport end to end: real git client, real receive-pack, the
//! real hook binary, and the graph.
//!
//! Two flows: a single change through clone → push → amend → review →
//! merge → verified fresh clone, and a three-commit stack with parent
//! links, per-change amends, guard rails, and bottom-up merges.

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

struct Forge {
    _tmp: tempfile::TempDir,
    app: Router,
    addr: SocketAddr,
    work: PathBuf,
    scout_token: String,
}

/// Boot a forge with git hosting, principals (human `ada`, agents
/// `scout` and `arbiter` of distinct models), and a repo `demo`.
async fn boot() -> Forge {
    boot_with("sha1").await
}

async fn boot_with(object_format: &str) -> Forge {
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
    let app = router(
        AppState::new(store)
            .with_dev_identity()
            .with_git(git_store, format!("http://{addr}")),
    );
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

fn git(dir: &Path, args: &[&str]) -> String {
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
fn git_expect_fail(dir: &Path, args: &[&str]) -> String {
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

fn git_raw(dir: &Path, args: &[&str]) -> std::process::Output {
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

/// Satisfy default policy for a change and merge it: passing test claim
/// from the agent, human approval, merge as the human.
async fn approve_and_merge(app: &Router, change_id: &str) -> Value {
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

fn commit_file(wc: &Path, file: &str, contents: &str, message: &str) {
    std::fs::write(wc.join(file), contents).unwrap();
    git(wc, &["add", "."]);
    git(wc, &["commit", "-m", message]);
}

#[tokio::test(flavor = "multi_thread")]
async fn push_review_merge_over_real_git() {
    single_change_flow(boot().await, 40).await;
}

/// The identical flow on a SHA-256 object database: 64-char oids end
/// to end, from clone through merge.
#[tokio::test(flavor = "multi_thread")]
async fn push_review_merge_sha256_repo() {
    single_change_flow(boot_with("sha256").await, 64).await;
}

async fn single_change_flow(forge: Forge, oid_len: usize) {
    let (app, addr) = (&forge.app, forge.addr);

    // Clone (anonymous reads), commit with a Change-Id trailer.
    git(
        &forge.work,
        &["clone", &format!("http://{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "greeting.txt",
        "hello\n",
        "Add greeting\n\nChange-Id: If00dcafe01",
    );
    let first_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    assert_eq!(
        first_oid.len(),
        oid_len,
        "object format should determine oid width"
    );

    // Anonymous pushes are refused before touching receive-pack.
    git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    // The transport IS the API: push with scout's real token as the
    // Basic password (dev mode would also accept it; the strict path
    // has its own test below).
    let push_url = format!("http://scout:{}@{addr}/git/demo", forge.scout_token);
    git(&wc, &["remote", "set-url", "origin", &push_url]);
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (status, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
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

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(
        changes.as_array().unwrap().len(),
        1,
        "amend must not open a second change"
    );
    assert_eq!(changes[0]["latest_revision"], 2);

    // Every revision stays fetchable by its stable ref.
    git(&wc, &["fetch", "origin", "refs/changes/1/1"]);
    assert_eq!(git(&wc, &["rev-parse", "FETCH_HEAD"]).trim(), first_oid);

    // Capability precedes policy: scout cannot merge at all, and even
    // the sovereign human is refused until policy is satisfied.
    let (status, refusal) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "scout",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(refusal["kind"], "forbidden");
    let (status, refusal) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal["kind"], "policy_unsatisfied");

    let merged = approve_and_merge(app, &change_id).await;
    assert_eq!(merged["event"]["kind"], "change_merged");
    assert_eq!(merged["event"]["revision"], 2);

    let main_ref = git(&wc, &["ls-remote", "origin", "refs/heads/main"]);
    assert!(
        main_ref.starts_with(&second_oid),
        "main should point at revision 2 ({second_oid}); got:\n{main_ref}"
    );

    // A fresh clone sees the merged history — the loop is closed.
    git(
        &forge.work,
        &["clone", &format!("http://{addr}/git/demo"), "verify"],
    );
    let contents = std::fs::read_to_string(forge.work.join("verify/greeting.txt")).unwrap();
    assert_eq!(contents, "hello, forge\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn stacked_push_with_guards_and_bottom_up_merge() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");

    // A three-commit stack, each commit carrying its own Change-Id.
    commit_file(
        &wc,
        "base.txt",
        "base\n",
        "Lay the base\n\nChange-Id: Iaaa01",
    );
    commit_file(
        &wc,
        "mid.txt",
        "mid\n",
        "Build the middle\n\nChange-Id: Iaaa02",
    );
    commit_file(&wc, "top.txt", "top\n", "Cap the top\n\nChange-Id: Iaaa03");
    let oids: Vec<String> = ["HEAD~2", "HEAD~1", "HEAD"]
        .iter()
        .map(|r| git(&wc, &["rev-parse", r]).trim().to_owned())
        .collect();

    // Guard: branches advance only by merge, never by direct push.
    let refused = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(
        refused.contains("direct push"),
        "unexpected refusal:\n{refused}"
    );

    // One push, three linked changes, bottom-up numbering.
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let changes = changes.as_array().unwrap().clone();
    assert_eq!(changes.len(), 3);
    for (index, change) in changes.iter().enumerate() {
        assert_eq!(change["number"], index as i64 + 1);
        assert_eq!(change["latest_revision"], 1);
        if index == 0 {
            assert!(change["parent_change"].is_null());
        } else {
            assert_eq!(
                change["parent_change"],
                changes[index - 1]["id"],
                "stack link broken"
            );
        }
    }
    let refs = git(&wc, &["ls-remote", "origin"]);
    for number in 1..=3 {
        assert!(
            refs.contains(&format!("refs/changes/{number}/1")),
            "missing ref:\n{refs}"
        );
    }

    // Re-pushing the identical stack records nothing new.
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, unchanged) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert!(
        unchanged
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["latest_revision"] == 1),
        "idempotent re-push must not mint revisions"
    );

    // Amending only the top commit touches only the top change.
    std::fs::write(wc.join("top.txt"), "top, improved\n").unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &[
            "commit",
            "--amend",
            "-m",
            "Cap the top\n\nChange-Id: Iaaa03",
        ],
    );
    let amended_top = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, after) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let revisions: Vec<i64> = after
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["latest_revision"].as_i64().unwrap())
        .collect();
    assert_eq!(
        revisions,
        [1, 1, 2],
        "only the amended change may gain a revision"
    );

    // A stack without per-commit Change-Ids is refused with advice.
    git(&wc, &["checkout", "-q", "-b", "naked", "HEAD~2"]);
    commit_file(&wc, "a.txt", "a\n", "no trailer here");
    commit_file(&wc, "b.txt", "b\n", "none here either");
    let refused = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/dev"]);
    assert!(
        refused.contains("Change-Id"),
        "unexpected refusal:\n{refused}"
    );

    // Merge bottom-up; each merge fast-forwards main to that commit.
    let expected_tips = [oids[0].clone(), oids[1].clone(), amended_top.clone()];
    for (change, expected_tip) in after.as_array().unwrap().iter().zip(&expected_tips) {
        let change_id = change["id"].as_str().unwrap();
        approve_and_merge(app, change_id).await;
        let main_ref = git(&wc, &["ls-remote", "origin", "refs/heads/main"]);
        assert!(
            main_ref.starts_with(expected_tip.as_str()),
            "after merging change {}, main should be {expected_tip}; got:\n{main_ref}",
            change["number"]
        );
    }
}

/// Push credentials are real: with dev identity off, only a live API
/// token as the Basic password gets through receive-pack.
#[tokio::test(flavor = "multi_thread")]
async fn push_requires_a_live_token_without_dev_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    let ada = PrincipalId::new("ada").unwrap();
    let scout = PrincipalId::new("scout").unwrap();
    store
        .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
        .unwrap();
    store
        .register_principal(&ada, &scout, PrincipalKind::Agent, "Scout", Some("m"), None)
        .unwrap();
    store
        .issue_grant(&ada, &scout, None, vec![cairn_core::Capability::Push], None)
        .unwrap();
    let (_, token, _) = store.mint_token(&scout, &scout, None).unwrap();
    store
        .create_repo(&ada, "demo", "main", cairn_core::ObjectFormat::Sha1)
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let git_store = GitStore::new(&repos, env!("CARGO_BIN_EXE_cairn"));
    // The repo entered the graph through the store, so create the bare
    // repo directly too; no dev identity anywhere in this test.
    git_store.create_repo("demo", "main", "sha1").await.unwrap();
    let app = router(AppState::new(store).with_git(git_store, format!("http://{addr}")));
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    git(&work, &["clone", &format!("http://{addr}/git/demo"), "wc"]);
    let wc = work.join("wc");
    commit_file(&wc, "f.txt", "x\n", "Add f\n\nChange-Id: Itok01");

    // Wrong password refused; bare username refused.
    for bad in [
        format!("http://scout:wrong@{addr}/git/demo"),
        format!("http://scout@{addr}/git/demo"),
    ] {
        let output = git_raw(&wc, &["push", &bad, "HEAD:refs/for/main"]);
        assert!(
            !output.status.success(),
            "push with bad credentials must fail"
        );
    }

    // The live token authenticates and the change lands on the wire.
    git(
        &wc,
        &[
            "push",
            &format!("http://scout:{token}@{addr}/git/demo"),
            "HEAD:refs/for/main",
        ],
    );
    let refs = git(&wc, &["ls-remote", &format!("http://{addr}/git/demo")]);
    assert!(
        refs.contains("refs/changes/1/1"),
        "missing change ref:\n{refs}"
    );
}
