//! Pages for what exists: tasks with their sessions and changes, the
//! landing policy with a preview, the mirror, and the forge-wide log.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn tasks_have_a_page_with_their_runs_and_changes() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, task) = api(app, "POST", "/api/tasks", "ada", Some(json!({ "title": "Teach the forge to page", "spec": "Lists page by cursor.\nNothing else changes.", "repo": "demo" }))).await;
    let task_id = task["id"].as_str().unwrap().to_owned();
    api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/claim"),
        &forge.scout_token,
        None,
    )
    .await;
    let (_, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/sessions"),
        &forge.scout_token,
        None,
    )
    .await;
    let session_id = session["id"].as_str().unwrap();
    api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Paging", "task": task_id })),
    )
    .await;
    api_with_token(
        app,
        "POST",
        &format!("/api/sessions/{session_id}/end"),
        &forge.scout_token,
        Some(json!({ "state": "completed", "outcome": "Opened #1 with the paging." })),
    )
    .await;

    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, list) = page_with_cookie(app, "/tasks", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        list.contains("Teach the forge to page") && list.contains(r#"href="/tasks?state=claimed""#),
        "{list}"
    );
    let (_, claimed) = page_with_cookie(app, "/tasks?state=landed", &ada).await;
    assert!(!claimed.contains("Teach the forge to page"), "{claimed}");
    let (status, page) = page_with_cookie(app, &format!("/tasks/{task_id}"), &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Lists page by cursor."), "{page}");
    assert!(
        page.contains("Opened #1 with the paging."),
        "the session's outcome: {page}"
    );
    assert!(
        page.contains(r#"href="/demo/changes/1""#),
        "the change that came of it: {page}"
    );
    assert!(page.contains("held by scout"), "{page}");
    // The creator can close it from the page.
    let (status, location) =
        post_form(app, &format!("/tasks/{task_id}"), &ada, "state=landed").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, t) = api(app, "GET", &format!("/api/tasks/{task_id}"), "ada", None).await;
    assert_eq!(t["state"], "landed");
    // The sidebar knows the page.
    assert!(page.contains(r#"class="on" href="/tasks""#), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_policy_can_be_previewed_and_saved_from_settings_and_the_mirror_set() {
    let forge = boot().await;
    let app = &forge.app;
    // An open change with a passing claim but no approval.
    let (_, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Needs a human" })),
    )
    .await;
    let id = change["id"].as_str().unwrap();
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "f".repeat(40), "message": "x" })),
    )
    .await;
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{id}/claims"),
        &forge.scout_token,
        Some(json!({ "kind": "test", "command": "cargo test", "passed": true, "summary": "ok" })),
    )
    .await;

    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, settings) = page_with_cookie(app, "/demo/settings", &ada).await;
    assert!(settings.contains("Landing policy"), "{settings}");
    assert!(
        settings.contains("Mirror"),
        "ada runs the forge: {settings}"
    );
    // Preview a stricter policy: it would hold the change, and saves nothing.
    let (status, preview) = post_form_page(app, "/demo/settings/policy", &ada,
        "action=preview&require_executed_check=on&require_runner_verification=on&independence=human_only&domains=security&attention_budget=").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview.contains("would hold 1"), "{preview}");
    assert!(preview.contains("Needs a human"), "{preview}");
    let (_, policy) = api(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert_eq!(
        policy["require_runner_verification"], false,
        "a preview changes nothing"
    );
    // Save it: the API sees it, with both domains and a budget.
    let (status, location) = post_form(app, "/demo/settings/policy", &ada,
        "action=save&require_executed_check=on&independence=human_only&domains=security&domains=design&attention_budget=2&require_concerns_resolved=on").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, policy) = api(app, "GET", "/api/repos/demo/policy", "ada", None).await;
    assert_eq!(policy["independence"], "human_only");
    assert_eq!(policy["required_domains"], json!(["security", "design"]));
    assert_eq!(policy["attention_budget"], 2);
    assert_eq!(policy["require_concerns_resolved"], true);
    assert_eq!(policy["agents_act_in_sessions"], false);
    // The mirror, from the same page.
    let (status, location) = post_form(
        app,
        "/demo/settings/mirror",
        &ada,
        "url=https%3A%2F%2Fexample.test%2Fmirror.git&enabled=on",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    let (_, repo) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(repo["mirror"]["url"], "https://example.test/mirror.git");
    let (_, settings) = page_with_cookie(app, "/demo/settings", &ada).await;
    assert!(
        settings.contains("https://example.test/mirror.git"),
        "{settings}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn whoever_runs_the_forge_reads_the_whole_log() {
    let forge = boot().await;
    let app = &forge.app;
    api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Something" })),
    )
    .await;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, log) = page_with_cookie(app, "/log", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(log.contains("Forge log"), "{log}");
    assert!(
        log.contains("created demo") && log.contains("opened"),
        "{log}"
    );
    assert!(
        log.contains(r#"href="/demo/log""#),
        "events name their repository: {log}"
    );
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (status, _) = page_with_cookie(app, "/log", &bee).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, home) = page_with_cookie(app, "/", &bee).await;
    assert!(!home.contains(r#"href="/log""#), "{home}");
}
