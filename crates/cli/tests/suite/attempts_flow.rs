//! The task as the unit of review: one task, one open change, every
//! attempt a revision of it, and a comparison that says which lands.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::path::Path;

async fn ok(app: &Router, method: &str, path: &str, actor: &str, body: Option<Value>) -> Value {
    let (status, value) = api(app, method, path, actor, body).await;
    assert_eq!(status, StatusCode::OK, "{method} {path}: {value}");
    value
}

async fn requirement(app: &Router, change: &str, needle: &str) -> Value {
    let trace = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    trace["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains(needle))
        .cloned()
        .unwrap_or_else(|| panic!("no requirement containing {needle:?} in {trace}"))
}

fn push_attempt(wc: &Path, file: &str, message: &str) -> String {
    commit_file(wc, file, "attempt\n", message);
    git(wc, &["push", "-q", "-f", "origin", "HEAD:refs/for/main"]);
    git(wc, &["rev-parse", "HEAD"]).trim().to_owned()
}

fn amend_and_push(wc: &Path, file: &str) -> String {
    std::fs::write(wc.join(file), "attempt, amended\n").unwrap();
    git(wc, &["add", "."]);
    git(wc, &["commit", "-q", "--amend", "--no-edit"]);
    git(wc, &["push", "-q", "-f", "origin", "HEAD:refs/for/main"]);
    git(wc, &["rev-parse", "HEAD"]).trim().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_attempts_are_revisions_of_one_change_and_a_reviewer_compares() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    ok(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "arbiter", "actions": ["task", "push"] })),
    )
    .await;

    // A task that invites two attempts; a third claimant is refused.
    let created = ok(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({
            "repo": "ada/demo", "title": "Name the files in a conflict",
            "spec": "The dequeue reason should list the paths.", "attempts": 2
        })),
    )
    .await;
    let task = created["id"].as_str().unwrap().to_owned();
    ok(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        "scout",
        None,
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        "arbiter",
        None,
    )
    .await;
    let (status, refused) = api(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("invites 2 attempt(s)"),
        "{refused}"
    );
    let shown = ok(app, "GET", &format!("/api/tasks/{task}"), "ada", None).await;
    assert_eq!(shown["attempts"], 2);
    assert_eq!(shown["claimants"], json!(["scout", "arbiter"]));
    assert_eq!(
        shown["claimed_by"], "scout",
        "the first claimant, for what already reads it"
    );
    let s_scout = ok(
        app,
        "POST",
        &format!("/api/tasks/{task}/sessions"),
        "scout",
        None,
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let s_arbiter = ok(
        app,
        "POST",
        &format!("/api/tasks/{task}/sessions"),
        "arbiter",
        None,
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Scout's attempt arrives by git, naming the task in a trailer.
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/ada/demo"),
            "scout",
        ],
    );
    let scout = forge.work.join("scout");
    let r1_oid = push_attempt(
        &scout,
        "queue.rs",
        &format!("Read the paths from the rebase result\n\nChange-Id: Iscout\nTask: {task}"),
    );
    let changes = ok(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    assert_eq!(changes.as_array().unwrap().len(), 1);
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(changes[0]["task"], task);

    // Arbiter's attempt, a different commit under a different key, is a
    // revision of the same change, not a second change.
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://arbiter:x@{addr}/git/ada/demo"),
            "arbiter",
        ],
    );
    let arbiter = forge.work.join("arbiter");
    push_attempt(
        &arbiter,
        "stderr.rs",
        &format!("Parse the paths out of git's stderr\n\nChange-Id: Iarbiter\nTask: {task}"),
    );
    let changes = ok(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    assert_eq!(
        changes.as_array().unwrap().len(),
        1,
        "one task, one change: {changes}"
    );
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["latest_revision"], 2);
    assert_eq!(shown["competing"], true, "{shown}");
    assert!(shown["preferred_revision"].is_null());
    let revisions = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/revisions"),
        "ada",
        None,
    )
    .await;
    assert_eq!(revisions[0]["by"], "scout");
    assert_eq!(
        revisions[0]["session"], s_scout,
        "the revision says which attempt it came from"
    );
    assert_eq!(revisions[1]["by"], "arbiter");
    assert_eq!(revisions[1]["session"], s_arbiter);

    // Opening another change against the task is refused, with a pointer.
    let (status, refused) = api(
        app,
        "POST",
        "/api/changes",
        "arbiter",
        Some(json!({ "repo": "ada/demo", "target": "main", "title": "Another go", "task": task })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains(&change),
        "{refused}"
    );

    // Competing revisions cannot land until somebody compares them, and
    // an author of one may not be that somebody.
    let comparison = requirement(app, &change, "competing revisions").await;
    assert_eq!(comparison["satisfied"], false, "{comparison}");
    let (status, body) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/prefer"),
        "scout",
        Some(json!({ "revision": 1, "rationale": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/prefer"),
        "ada",
        Some(json!({ "revision": 2, "rationale": "Cheaper, and the format risk is acceptable for now." })),
    )
    .await;
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["preferred_revision"], 2);
    assert_eq!(
        requirement(app, &change, "competing revisions").await["satisfied"],
        true
    );

    // The preferred author's later push carries the preference; anyone
    // else's reopens the comparison.
    let r3_oid = amend_and_push(&arbiter, "stderr.rs");
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["latest_revision"], 3);
    assert_eq!(shown["preferred_revision"], 3, "{shown}");
    amend_and_push(&scout, "queue.rs");
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["latest_revision"], 4);
    assert!(shown["preferred_revision"].is_null(), "reopened: {shown}");
    assert_eq!(
        requirement(app, &change, "competing revisions").await["satisfied"],
        false
    );
    let _ = r1_oid;

    // Compared again, judged and landed: the preferred revision is what
    // the policy reads and what lands, and the task lands with it.
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/prefer"),
        "ada",
        Some(json!({ "revision": 3, "rationale": "r4 rewrote the test to pass; r3's approach still reads better." })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "arbiter",
        Some(json!({ "revision": 3, "kind": "test", "passed": true, "summary": "green", "command": "exit 0" })),
    )
    .await;
    // The runner re-runs the preferred revision's claims, not the latest's.
    ok(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "runner", "kind": "agent", "display": "Runner", "model": "sandbox", "harness": "ci" })),
    )
    .await;
    ok(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "runner", "actions": ["verify"] })),
    )
    .await;
    let runner_token = ok(
        app,
        "POST",
        "/api/principals/runner/tokens",
        "ada",
        Some(json!({ "label": "ci" })),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let workspace = forge.work.join("runner");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args([
            "verify",
            "--server",
            &format!("http://{addr}"),
            "--token",
            &runner_token,
            "--repo",
            "ada/demo",
            "--workdir",
            workspace.to_str().unwrap(),
            "--checkout",
            "1",
        ])
        .output()
        .expect("run the runner");
    let said = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{said}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said.contains("re-run on revision 3"),
        "the preferred revision, not the latest: {said}"
    );
    let verifications = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/verifications?revision=3"),
        "ada",
        None,
    )
    .await;
    assert_eq!(
        verifications.as_array().unwrap().len(),
        1,
        "{verifications}"
    );
    assert_eq!(verifications[0]["by"], "runner");
    // The page opens on the judged revision: r3 carries the claim, r4 none.
    let (status, page) = page_with_cookie(app, "/ada/demo/changes/1", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("green"),
        "the page should open on r3, the preferred revision: {page}"
    );
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/verdicts"),
        "ada",
        Some(json!({ "revision": 3, "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    let trace = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(trace["satisfied"], true, "{trace}");
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/merge"),
        "ada",
        None,
    )
    .await;
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["state"], "merged");
    assert_eq!(
        shown["landed_oid"], r3_oid,
        "the preferred revision landed, not the latest"
    );
    let landed_task = ok(app, "GET", &format!("/api/tasks/{task}"), "ada", None).await;
    assert_eq!(landed_task["state"], "landed", "{landed_task}");
    let receipt = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/receipt"),
        "ada",
        None,
    )
    .await;
    assert_eq!(receipt["receipt"]["revision"]["number"], 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_of_one_attempt_is_exclusive_as_before() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, refused) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "Too many", "spec": "s", "attempts": 9 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let task = ok(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "Solo", "spec": "One agent's work." })),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        "scout",
        None,
    )
    .await;
    let (status, refused) = api(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    let (status, again) = api(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        "scout",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");
    assert!(again["error"].as_str().unwrap().contains("already holds"));
    let shown = ok(app, "GET", &format!("/api/tasks/{task}"), "ada", None).await;
    assert_eq!(shown["attempts"], 1);
    assert_eq!(shown["claimants"], json!(["scout"]));

    // A single author's revisions are history, not competition.
    let change = ok(
        app,
        "POST",
        "/api/changes",
        "scout",
        Some(json!({ "repo": "ada/demo", "target": "main", "title": "Solo change", "task": task })),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for oid in ["a", "b"] {
        ok(
            app,
            "POST",
            &format!("/api/changes/{change}/revisions"),
            "scout",
            Some(json!({ "commit_oid": oid.repeat(40) })),
        )
        .await;
    }
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["competing"], false);
    let (status, body) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/prefer"),
        "ada",
        Some(json!({ "revision": 1, "rationale": "nothing to compare" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let trace = ok(
        app,
        "GET",
        &format!("/api/changes/{change}/readiness"),
        "ada",
        None,
    )
    .await;
    assert!(
        !trace["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["description"].as_str().unwrap().contains("competing")),
        "{trace}"
    );
}
