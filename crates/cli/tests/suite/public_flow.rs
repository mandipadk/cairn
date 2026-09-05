//! Public means public: a public repository is readable without signing
//! in, on its pages and over its read-only API, with nothing to act on;
//! a private one still answers a stranger as if it were not there.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

async fn public_demo_with_a_change(forge: &Forge) -> String {
    let app = &forge.app;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/demo/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Seen by anyone" })),
    )
    .await;
    let id = change["id"].as_str().unwrap().to_owned();
    api_with_token(
        app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "a".repeat(40), "message": "work" })),
    )
    .await;
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_public_repository_reads_without_signing_in_and_offers_nothing_to_do() {
    let forge = boot().await;
    let app = &forge.app;
    let id = public_demo_with_a_change(&forge).await;

    for path in [
        "/demo",
        "/demo/changes",
        "/demo/changes/1",
        "/demo/log",
        "/demo/landing",
        "/demo/lessons",
    ] {
        let (status, page) = page_with_cookie(app, path, "").await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            page.contains(r#"href="/login""#),
            "{path} offers to sign in: {page}"
        );
        assert!(!page.contains("Sign out"), "{path}");
        assert!(
            !page.contains(r#"href="/inbox""#),
            "{path} shows nothing personal"
        );
        assert!(
            !page.contains(r#"action="/theme"#) || !page.contains("Approve"),
            "{path}"
        );
    }
    let (_, change_page) = page_with_cookie(app, "/demo/changes/1", "").await;
    assert!(
        !change_page.contains("Approve"),
        "no verdict form for a stranger: {change_page}"
    );
    assert!(
        !change_page.contains("at=new:"),
        "no thread composer for a stranger"
    );
    assert!(change_page.contains("Seen by anyone"));

    // The read-only API answers without a token, exactly as it would with one.
    for path in [
        "/api/repos/demo".to_owned(),
        "/api/repos/demo/changes".to_owned(),
        format!("/api/changes/{id}"),
        format!("/api/changes/{id}/readiness"),
        format!("/api/changes/{id}/threads"),
        "/api/repos/demo/policy".to_owned(),
        "/api/repos/demo/attention".to_owned(),
    ] {
        let (status, body) = api_anonymous(app, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    // Writing still needs identity.
    let (status, _) = api_anonymous(
        app,
        "POST",
        "/api/changes",
        Some(json!({ "repo": "demo", "target": "main", "title": "Nope" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, location) = post_form(
        app,
        "/demo/changes/1/threads",
        "",
        "revision=1&on=change&kind=note&body=hi",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/login");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_private_repository_still_answers_a_stranger_as_if_it_were_not_there() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, _) = api_anonymous(app, "GET", "/api/repos/demo", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api_anonymous(app, "GET", "/api/repos/nothing", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, location) = get_redirect(app, "/demo", "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/login");
    // A bad token is refused, not downgraded to a stranger.
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", "cairn_nope", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
