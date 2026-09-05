//! The forge as credential broker: a session draws a short-lived,
//! scoped credential; it buys exactly what it carries, over the API and
//! over git, and dies with the session.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

/// A claimed task in `demo` with an open session, as scout.
async fn open_session(forge: &Forge) -> (String, String) {
    let app = &forge.app;
    let (status, task) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &forge.ada_token,
        Some(json!({ "title": "Broker work", "spec": "Do the work in demo.", "repo": "demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{task}");
    let task_id = task["id"].as_str().unwrap().to_owned();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/claim"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/sessions"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    (task_id, session["id"].as_str().unwrap().to_owned())
}

async fn credential(forge: &Forge, session: &str, body: Value) -> (StatusCode, Value) {
    api_with_token(
        &forge.app,
        "POST",
        &format!("/api/sessions/{session}/credential"),
        &forge.scout_token,
        Some(body),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_credential_carries_its_scope_and_dies_with_the_session() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, session) = open_session(&forge).await;

    let (status, drawn) = credential(&forge, &session, json!({ "minutes": 30 })).await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    let token = drawn["token"].as_str().unwrap().to_owned();
    assert_eq!(drawn["scope"]["repo"], "demo");
    assert_eq!(drawn["scope"]["session"], session);
    let actions = drawn["scope"]["actions"].as_array().unwrap();
    assert!(
        actions.iter().any(|a| a == "push") && actions.iter().any(|a| a == "task"),
        "{drawn}"
    );
    assert!(
        !actions.iter().any(|a| a == "review"),
        "scout holds no review: {drawn}"
    );

    // Inside its scope the credential is scout.
    let (status, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Under a session credential" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    assert_eq!(change["event"]["actor"], "scout");

    // Outside it the credential is nothing, though scout's grants reach there.
    let (status, other) = api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "other" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{other}");
    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &token,
        Some(json!({ "repo": "other", "target": "main", "title": "Reaching" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("outside it"),
        "{refused}"
    );
    let (status, _) = api_with_token(app, "GET", "/api/repos/other", &token, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a scoped credential cannot even see other repositories"
    );
    let (status, _) =
        api_with_token(app, "GET", "/api/repos/other", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::OK, "the standing token still can");
    // A verb it does not carry is refused before grants are consulted.
    let change_id = change["id"].as_str().unwrap();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/changes/{change_id}/verdicts"),
        &token,
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "no" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Ending the session kills the credential; the standing token lives on.
    let (status, ended) = api_with_token(
        app,
        "POST",
        &format!("/api/sessions/{session}/end"),
        &token,
        Some(json!({ "state": "completed", "outcome": "Opened one change under a session credential." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ended}");
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = credential(&forge, &session, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "a dead session draws nothing");

    // The log says what was drawn and that it died, and never the secret.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, log) = page_with_cookie(app, "/demo/log", &cookie).await;
    assert!(log.contains("drew a credential from session"), "{log}");
    assert!(log.contains("credential died with it"), "{log}");
    assert!(!log.contains(&token), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_never_carries_more_than_its_holder_or_its_parent() {
    let forge = boot().await;
    let (_, session) = open_session(&forge).await;
    let (status, refused) = credential(&forge, &session, json!({ "actions": ["merge"] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, refused) = credential(&forge, &session, json!({ "minutes": 0 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, narrow) = credential(&forge, &session, json!({ "actions": ["task"] })).await;
    assert_eq!(status, StatusCode::OK, "{narrow}");
    // From inside a task-only credential, a push credential is out of reach.
    let (status, refused) = api_with_token(
        &forge.app,
        "POST",
        &format!("/api/sessions/{session}/credential"),
        narrow["token"].as_str().unwrap(),
        Some(json!({ "actions": ["push"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    // Only the session's agent draws from it.
    let (status, _) = api(
        &forge.app,
        "POST",
        &format!("/api/sessions/{session}/credential"),
        "ada",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_can_insist_that_agents_act_inside_sessions() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/demo/policy",
        "ada",
        Some(json!({
            "require_executed_check": true,
            "independence": "human_or_two_models",
            "require_runner_verification": false,
            "required_domains": [],
            "agents_act_in_sessions": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The standing token can no longer push here, and is told what to do instead.
    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Standing" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("inside a session"),
        "{refused}"
    );
    // It can still claim a task and open a session; the credential then works.
    let (_, session) = open_session(&forge).await;
    let (status, drawn) = credential(&forge, &session, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    let (status, opened) = api_with_token(
        app,
        "POST",
        "/api/changes",
        drawn["token"].as_str().unwrap(),
        Some(json!({ "repo": "demo", "target": "main", "title": "In session" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    // People are not agents.
    let (status, _) = api(
        app,
        "POST",
        "/api/changes",
        "ada",
        Some(json!({ "repo": "demo", "target": "main", "title": "By hand" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn git_takes_a_session_credential_and_refuses_it_after_the_session() {
    // Without dev identity, so that an unknown password is refused rather
    // than taken as an asserted name.
    let forge = boot_token_only().await;
    let addr = forge.addr;
    let (_, session) = open_session(&forge).await;
    let (_, drawn) = credential(&forge, &session, json!({})).await;
    let token = drawn["token"].as_str().unwrap().to_owned();

    git(
        &forge.work,
        &[
            "clone",
            &format!("http://scout:{token}@{addr}/git/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "a.txt", "one\n", "Add a\n\nChange-Id: Icred0001");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api_with_token(
        &forge.app,
        "GET",
        "/api/repos/demo/changes",
        &forge.ada_token,
        None,
    )
    .await;
    assert_eq!(changes.as_array().unwrap().len(), 1, "{changes}");
    assert_eq!(changes[0]["owner"], "scout");

    let (status, _) = api_with_token(
        &forge.app,
        "POST",
        &format!("/api/sessions/{session}/end"),
        &forge.scout_token,
        Some(json!({ "state": "completed", "outcome": "Pushed once over git under the credential." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    commit_file(&wc, "b.txt", "two\n", "Add b\n\nChange-Id: Icred0002");
    let refused = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    assert!(
        refused.contains("401") || refused.to_lowercase().contains("authentication"),
        "{refused}"
    );
}
