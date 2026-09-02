//! Notices reach whose work it is, over the API and on the page, and
//! reading them is the reader's business rather than the log's.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn work_on_your_change_lands_in_your_inbox_and_yours_alone() {
    let forge = boot().await;
    let app = &forge.app;

    // Scout opens a change in ada's repository: the owner is told, the
    // actor is not.
    let (status, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Scout's change" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let change = change["id"].as_str().unwrap().to_owned();

    let (_, ada) = api_with_token(app, "GET", "/api/inbox", &forge.ada_token, None).await;
    assert_eq!(ada["unread"], 1, "{ada}");
    assert_eq!(ada["notices"][0]["kind"], "opened");
    assert_eq!(ada["notices"][0]["number"], 1);
    let (_, scout) = api_with_token(app, "GET", "/api/inbox", &forge.scout_token, None).await;
    assert!(
        scout["notices"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["kind"] != "opened"),
        "the actor is not told about their own change: {scout}"
    );
    let scout_before = scout["unread"].as_i64().unwrap();

    // Ada's verdict is scout's news.
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{change}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "0".repeat(40), "message": "work" })),
    )
    .await;
    let (status, body) = api_with_token(
        app,
        "POST",
        &format!("/api/changes/{change}/verdicts"),
        &forge.ada_token,
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, scout) = api_with_token(app, "GET", "/api/inbox", &forge.scout_token, None).await;
    assert_eq!(scout["unread"], scout_before + 1, "{scout}");
    assert_eq!(scout["notices"][0]["kind"], "verdict");
    assert_eq!(scout["notices"][0]["actor"], "ada");

    // Reading is per item or all at once, and never touches the log.
    let seq = scout["notices"][0]["seq"].as_i64().unwrap();
    let (_, latest) = api_with_token(
        app,
        "GET",
        "/api/events?after=0&limit=1000",
        &forge.ada_token,
        None,
    )
    .await;
    let events_before = latest.as_array().unwrap().len();
    let (status, after) = api_with_token(
        app,
        "POST",
        "/api/inbox/read",
        &forge.scout_token,
        Some(json!({ "seq": seq })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(
        after["unread"], scout_before,
        "one item read, the rest untouched"
    );
    let (_, after) = api_with_token(
        app,
        "POST",
        "/api/inbox/read",
        &forge.ada_token,
        Some(json!({ "all": true })),
    )
    .await;
    assert_eq!(after["unread"], 0);
    let (_, latest) = api_with_token(
        app,
        "GET",
        "/api/events?after=0&limit=1000",
        &forge.ada_token,
        None,
    )
    .await;
    assert_eq!(
        latest.as_array().unwrap().len(),
        events_before,
        "reading is not an event"
    );

    // Neither is a malformed request.
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/inbox/read",
        &forge.ada_token,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_shows_the_count_and_the_words() {
    let forge = boot().await;
    let app = &forge.app;
    api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Scout's change" })),
    )
    .await;

    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/inbox", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("scout opened #1 in demo"),
        "the notice reads as a sentence"
    );
    assert!(page.contains("1 unread"));
    assert!(
        !page.contains(r#"class="repohead""#),
        "a section page is not a repository"
    );
    assert!(
        page.contains(r#"href="/demo/changes/1""#),
        "a notice links to its subject"
    );
    // The sidebar count is the same number, everywhere.
    let (_, home) = page_with_cookie(app, "/", &cookie).await;
    assert!(home.contains("Inbox"));
    assert!(home.contains(r#"<span class="n">1</span>"#), "{home}");

    // Marking all read from the page clears it.
    let (status, _) = post_form(app, "/inbox/read", &cookie, "all=1").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = page_with_cookie(app, "/inbox", &cookie).await;
    assert!(page.contains("0 unread"), "{page}");
}
