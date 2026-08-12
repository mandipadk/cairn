//! Fleet coordination over HTTP: two agents declaring intent over the
//! same files learn about each other before either has spent a session,
//! and the warning sharpens once one of them has actually pushed.

mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;

/// Claim a task and open a session for an agent, returning its id.
async fn session_for(app: &axum::Router, agent: &str, title: &str) -> String {
    let (status, task) = api(
        app,
        "POST",
        "/api/tasks",
        agent,
        Some(json!({ "repo": "demo", "title": title, "spec": "spec" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let task = task["id"].as_str().unwrap().to_owned();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        agent,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session) = api(
        app,
        "POST",
        &format!("/api/tasks/{task}/sessions"),
        agent,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    session["id"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_paths_warn_before_the_tokens_are_spent() {
    let forge = boot().await;
    let app = &forge.app;

    // arbiter needs push authority to hold ground.
    let (status, _) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "arbiter", "actions": ["task", "push", "review"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let scout_session = session_for(app, "scout", "Rework the parser").await;
    let arbiter_session = session_for(app, "arbiter", "Tune the parser cache").await;

    // First in finds open ground.
    let (status, first) = api(
        app,
        "POST",
        &format!("/api/sessions/{scout_session}/paths"),
        "scout",
        Some(json!({ "repo": "demo", "paths": ["crates/core/src/parser.rs", "docs/"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(first["overlaps"].as_array().unwrap().is_empty());

    // Second in is told who is there, where, and how far along.
    let (status, second) = api(
        app,
        "POST",
        &format!("/api/sessions/{arbiter_session}/paths"),
        "arbiter",
        Some(json!({ "repo": "demo", "paths": ["crates/core/"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let overlaps = second["overlaps"].as_array().unwrap();
    assert_eq!(overlaps.len(), 1);
    assert_eq!(overlaps[0]["holder"], "scout");
    assert_eq!(overlaps[0]["paths"][0], "crates/core/src/parser.rs");
    assert_eq!(
        overlaps[0]["already_landed"], false,
        "nobody has pushed yet, so this is intent against intent"
    );

    // Asking before starting works without declaring anything.
    let (status, ahead) = api(
        app,
        "GET",
        "/api/repos/demo/conflicts?paths=crates/core/src/parser.rs,README.md",
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let holders: Vec<&str> = ahead["overlaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["holder"].as_str().unwrap())
        .collect();
    assert!(holders.contains(&"scout") && holders.contains(&"arbiter"));

    // Once code exists, the warning says a rebase is coming.
    git(
        &forge.work,
        &[
            "clone",
            &format!("http://scout:x@{}/git/demo", forge.addr),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "parser.rs",
        "fn parse() {}\n",
        "Parser\n\nChange-Id: Iparser",
    );
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        "scout",
        Some(json!({
            "commit_oid": "0123456789abcdef0123456789abcdef01234567",
            "session": scout_session,
            "message": "parser"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, ahead) = api(
        app,
        "GET",
        "/api/repos/demo/conflicts?paths=crates/core/src/parser.rs",
        "ada",
        None,
    )
    .await;
    let scout_overlap = ahead["overlaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["holder"] == "scout")
        .expect("scout should still hold the path");
    assert_eq!(
        scout_overlap["already_landed"], true,
        "a session that has pushed means a rebase is coming"
    );

    // Ending the session releases the ground it held.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/sessions/{scout_session}/end"),
        "scout",
        Some(json!({ "state": "completed", "outcome": "parser reworked" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, after) = api(
        app,
        "GET",
        "/api/repos/demo/conflicts?paths=crates/core/src/parser.rs",
        "ada",
        None,
    )
    .await;
    assert!(
        after["overlaps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["holder"] != "scout"),
        "a finished session must not keep holding ground"
    );

    // The repository page shows the fleet by what it is working on.
    let (_, leases) = api(app, "GET", "/api/repos/demo/leases", "ada", None).await;
    let held: Vec<&str> = leases
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["holder"].as_str().unwrap())
        .collect();
    assert_eq!(held, ["arbiter"]);
}
