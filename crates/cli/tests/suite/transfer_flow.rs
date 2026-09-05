//! Repository settings live on the repository, and ownership moves only
//! when the other side says yes - from the inbox, on a page the offeree
//! can see even before they can see the repository.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn ownership_is_offered_on_settings_and_accepted_from_the_inbox() {
    let forge = boot().await;
    let app = &forge.app;
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, bee) = sign_in_as(&forge, "bee").await;

    // Bee cannot see the repository, let alone its settings.
    assert_eq!(
        get_with_cookie(app, "/demo", &bee).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_with_cookie(app, "/demo/settings", &bee).await,
        StatusCode::NOT_FOUND
    );
    let (_, page) = page_with_cookie(app, "/demo", &ada).await;
    assert!(
        page.contains(r#"href="/demo/settings""#),
        "the owner gets a Settings tab"
    );

    // Visibility is a setting, not an API call.
    let (status, location) =
        post_form(app, "/demo/settings/visibility", &ada, "visibility=public").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/demo/settings?done=1");
    assert_eq!(
        get_with_cookie(app, "/demo", &bee).await,
        StatusCode::OK,
        "public now"
    );
    assert_eq!(
        get_with_cookie(app, "/demo/settings", &bee).await,
        StatusCode::NOT_FOUND,
        "reading is not owning"
    );

    // Ada offers demo to bee; bee is told, and answers from the offer page.
    let (_, location) =
        post_form(app, "/demo/settings/transfer", &ada, "action=offer&to=bee").await;
    assert_eq!(location, "/demo/settings?done=1");
    let (_, inbox) = page_with_cookie(app, "/inbox", &bee).await;
    assert!(
        inbox.contains("ada offered you ownership of demo"),
        "{inbox}"
    );
    assert!(inbox.contains(r#"href="/demo/transfer""#));
    let (status, page) = page_with_cookie(app, "/demo/transfer", &bee).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("has offered you"));
    assert_eq!(
        get_with_cookie(app, "/demo/transfer", &ada).await,
        StatusCode::NOT_FOUND,
        "not ada's to answer"
    );

    let (status, location) = post_form(app, "/demo/transfer", &bee, "action=accept").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/demo");
    let (_, repo) = api_with_token(app, "GET", "/api/repos/demo", &forge.ada_token, None).await;
    assert_eq!(repo["owner"], "bee");

    // The tab moved with the ownership.
    let (_, page) = page_with_cookie(app, "/demo", &bee).await;
    assert!(page.contains(r#"href="/demo/settings""#));
    assert_eq!(
        get_with_cookie(app, "/demo/settings", &ada).await,
        StatusCode::OK,
        "ada runs the forge, so still sees it"
    );
}
