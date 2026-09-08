//! The task page as the review surface: attempts side by side, a
//! comparison made from the page, and the word reaching the inbox.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn ok(app: &Router, method: &str, path: &str, actor: &str, body: Option<Value>) -> Value {
    let (status, value) = api(app, method, path, actor, body).await;
    assert_eq!(status, StatusCode::OK, "{method} {path}: {value}");
    value
}

#[tokio::test(flavor = "multi_thread")]
async fn the_task_page_reads_the_attempts_and_takes_the_comparison() {
    let forge = boot().await;
    let app = &forge.app;
    ok(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "arbiter", "actions": ["task", "push"] })),
    )
    .await;
    let task = ok(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "Two ways in", "spec": "Try both.", "attempts": 2 })),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for agent in ["scout", "arbiter"] {
        ok(
            app,
            "POST",
            &format!("/api/tasks/{task}/claim"),
            agent,
            None,
        )
        .await;
    }
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
    let change = ok(
        app,
        "POST",
        "/api/changes",
        "scout",
        Some(json!({ "repo": "ada/demo", "target": "main", "title": "Two ways in", "task": task })),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        "scout",
        Some(json!({ "commit_oid": "a".repeat(40), "session": s_scout, "paths": ["a.rs"] })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        "arbiter",
        Some(json!({ "commit_oid": "b".repeat(40), "session": s_arbiter, "paths": ["b.rs", "c.rs"] })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "arbiter",
        Some(json!({ "revision": 2, "kind": "test", "passed": true, "summary": "green", "command": "exit 0" })),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("/api/sessions/{s_arbiter}/end"),
        "arbiter",
        Some(json!({ "state": "completed", "outcome": "Parsed the paths out of stderr; cheaper but format-bound." })),
    )
    .await;

    // Both attempts, their evidence and their words, and the form.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, &format!("/tasks/{task}"), &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Attempts"), "{page}");
    assert!(page.contains("claimed by 2 of 2"), "{page}");
    assert!(
        page.contains("r1 aaaaaaa") && page.contains("r2 bbbbbbb"),
        "{page}"
    );
    assert!(page.contains("(2 files)"), "{page}");
    assert!(
        page.contains("cheaper but format-bound"),
        "the outcome is on the page: {page}"
    );
    assert!(
        page.contains("competing revisions have a comparison"),
        "{page}"
    );
    assert!(
        page.contains(r#"name="revision""#) && page.contains("Prefer"),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="2">r2 by arbiter"#),
        "{page}"
    );

    // The comparison, made from the page, lands on the record and in the
    // owner's inbox; the page then shows it and the readiness line turns.
    let (status, location) = post_form(
        app,
        "/ada/demo/changes/1/prefer",
        &ada,
        "revision=2&rationale=r2+covers+more+and+carries+a+claim.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert_eq!(location, format!("/tasks/{task}"), "back to the task");
    let (_, page) = page_with_cookie(app, &format!("/tasks/{task}"), &ada).await;
    assert!(page.contains("preferred r2 over r1"), "{page}");
    assert!(
        page.contains("r2 covers more and carries a claim."),
        "{page}"
    );
    assert!(
        !page.contains(r#"name="revision""#),
        "no second comparison offered while one stands: {page}"
    );
    let shown = ok(app, "GET", &format!("/api/changes/{change}"), "ada", None).await;
    assert_eq!(shown["preferred_revision"], 2);
    let inbox = ok(app, "GET", "/api/inbox", "scout", None).await;
    let compared = inbox["notices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["kind"] == "compared")
        .unwrap_or_else(|| panic!("no comparison notice: {inbox}"));
    assert!(
        compared["what"]
            .as_str()
            .unwrap()
            .contains("preferred r2 of #1 over r1"),
        "{compared}"
    );

    // The change page says so too.
    let (_, page) = page_with_cookie(app, "/ada/demo/changes/1", &ada).await;
    assert!(page.contains("r2 preferred"), "{page}");
}
