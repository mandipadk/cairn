//! Reading is gated on the API and in the browser exactly as it is on
//! the git transport: a private repository answers a stranger the way a
//! missing one does, on every path that could describe it.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

/// Every read path the API offers for a repository, a change, a task
/// and a session, filled in for `demo` once the fixture exists.
fn read_paths(change: &str, task: &str, session: &str) -> Vec<String> {
    [
        "/api/repos/demo".to_owned(),
        "/api/repos/demo/changes".to_owned(),
        "/api/repos/demo/changes/1".to_owned(),
        "/api/repos/demo/queue".to_owned(),
        "/api/repos/demo/attention".to_owned(),
        "/api/repos/demo/awaiting-verification".to_owned(),
        "/api/repos/demo/conflicts?paths=src".to_owned(),
        "/api/repos/demo/leases".to_owned(),
        "/api/repos/demo/policy".to_owned(),
        "/api/repos/demo/mirror".to_owned(),
        "/api/lessons?repo=demo".to_owned(),
        format!("/api/changes/{change}"),
        format!("/api/changes/{change}/revisions"),
        format!("/api/changes/{change}/claims"),
        format!("/api/changes/{change}/verdicts"),
        format!("/api/changes/{change}/verifications"),
        format!("/api/changes/{change}/readiness"),
        format!("/api/tasks/{task}"),
        format!("/api/sessions/{session}"),
    ]
    .into_iter()
    .collect()
}

/// A second human with no grant on anything.
async fn stranger(forge: &Forge) -> String {
    api_with_token(
        &forge.app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, minted) = api_with_token(
        &forge.app,
        "POST",
        "/api/principals/bee/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    minted["token"].as_str().unwrap().to_owned()
}

/// Work in `demo`: a task, a session that ended with a lesson, and an
/// open change.
async fn populate(forge: &Forge) -> (String, String, String) {
    let app = &forge.app;
    let (status, task) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &forge.ada_token,
        Some(json!({ "repo": "demo", "title": "Private work", "spec": "quietly" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{task}");
    let task = task["id"].as_str().unwrap().to_owned();
    let (status, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task}/claim"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["event"]["kind"], "task_claimed");
    let (status, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task}/sessions"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let session = session["id"].as_str().unwrap().to_owned();
    let (status, ended) = api_with_token(
        app,
        "POST",
        &format!("/api/sessions/{session}/end"),
        &forge.scout_token,
        Some(json!({ "state": "failed", "outcome": "learned something private" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ended}");
    let (status, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.ada_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Private change" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    (change["id"].as_str().unwrap().to_owned(), task, session)
}

#[tokio::test(flavor = "multi_thread")]
async fn every_read_path_answers_a_stranger_as_if_nothing_were_there() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = stranger(&forge).await;
    let (change, task, session) = populate(&forge).await;

    // Whatever a missing repository answers is what a private one must
    // answer too - byte for byte, so nothing in the body tells them apart.
    let (_, missing) = api_with_token(app, "GET", "/api/repos/no-such-repo", &bee, None).await;
    for path in read_paths(&change, &task, &session) {
        let (theirs, body) = api_with_token(app, "GET", &path, &forge.ada_token, None).await;
        assert_eq!(theirs, StatusCode::OK, "owner reading {path}: {body}");
        let (status, body) = api_with_token(app, "GET", &path, &bee, None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "stranger reading {path}: {body}"
        );
        if path == "/api/repos/demo" {
            assert_eq!(
                body, missing,
                "private must be indistinguishable from missing"
            );
        }
    }

    // Cross-repository listings do not name what you may not see.
    let (_, tasks) = api_with_token(app, "GET", "/api/tasks", &bee, None).await;
    assert!(tasks.as_array().unwrap().is_empty(), "{tasks}");
    let (_, lessons) = api_with_token(app, "GET", "/api/lessons?q=private", &bee, None).await;
    assert!(lessons.as_array().unwrap().is_empty(), "{lessons}");

    // Once it is public, the same paths open - reading follows visibility.
    api_with_token(
        app,
        "POST",
        "/api/repos/demo/visibility",
        &forge.ada_token,
        Some(json!({ "visibility": "public" })),
    )
    .await;
    for path in read_paths(&change, &task, &session) {
        let (status, body) = api_with_token(app, "GET", &path, &bee, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "stranger reading public {path}: {body}"
        );
    }
    let (_, lessons) = api_with_token(app, "GET", "/api/lessons?q=private", &bee, None).await;
    assert_eq!(lessons.as_array().unwrap().len(), 1, "{lessons}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pages_keep_the_same_boundary() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    stranger(&forge).await;
    populate(&forge).await;
    let (_, cookie) = sign_in_as(&forge, "bee").await;

    for path in [
        "/demo",
        "/demo/tree/",
        "/demo/changes",
        "/demo/changes/1",
        "/demo/log",
        "/demo/lessons",
        "/demo/landing",
    ] {
        assert_eq!(
            get_with_cookie(app, path, &cookie).await,
            StatusCode::NOT_FOUND,
            "stranger opening {path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_changes_list_honours_its_state_filter() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let (change, _, _) = populate(&forge).await;
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{change}/abandon"),
        &forge.ada_token,
        Some(json!({ "reason": "changed my mind" })),
    )
    .await;

    let (_, open) = api_with_token(
        app,
        "GET",
        "/api/repos/demo/changes?state=open",
        &forge.ada_token,
        None,
    )
    .await;
    assert!(open.as_array().unwrap().is_empty(), "{open}");
    let (_, gone) = api_with_token(
        app,
        "GET",
        "/api/repos/demo/changes?state=abandoned",
        &forge.ada_token,
        None,
    )
    .await;
    assert_eq!(gone.as_array().unwrap().len(), 1, "{gone}");
    let (_, all) = api_with_token(
        app,
        "GET",
        "/api/repos/demo/changes",
        &forge.ada_token,
        None,
    )
    .await;
    assert_eq!(all.as_array().unwrap().len(), 1, "{all}");
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_are_listed_only_by_their_subject_or_an_admin() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = stranger(&forge).await;

    let (status, _) = api_with_token(app, "GET", "/api/principals/ada/tokens", &bee, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api_with_token(app, "GET", "/api/principals/bee/tokens", &bee, None).await;
    assert_eq!(status, StatusCode::OK);
    // Ada runs the forge, and revoking needs to see what exists.
    let (status, _) = api_with_token(
        app,
        "GET",
        "/api/principals/bee/tokens",
        &forge.ada_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
