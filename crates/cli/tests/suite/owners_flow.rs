//! An owner's page, and an organisation as an owner.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_page_shows_what_the_reader_may_see() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/ada", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"href="/ada/demo""#), "{page}");

    // With nothing public, the name is not confirmed to a stranger: an
    // owner who exists and one who does not look the same.
    let (status, _) = get_redirect(app, "/ada", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_redirect(app, "/nobody", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Once something is public, the stranger sees that and nothing else.
    api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "secret" })),
    )
    .await;
    api(
        app,
        "POST",
        "/api/repos/ada/demo/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    let (status, page) = page_with_cookie(app, "/ada", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"href="/ada/demo""#), "{page}");
    assert!(!page.contains("secret"), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_organisation_owns_what_its_members_make_under_it() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, location) = post_form(app, "/teams", &ada, "action=create&id=crew&display=Crew").await;
    assert_eq!(location, "/teams", "{location}");
    let (_, location) = post_form(app, "/teams", &ada, "action=add&team=crew&member=bee").await;
    assert_eq!(location, "/teams", "{location}");

    // Bee, a member and not running the forge, creates under crew from New.
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (_, new) = page_with_cookie(app, "/new", &bee).await;
    assert!(
        new.contains(r#"value="crew""#),
        "New offers the organisation: {new}"
    );
    let (status, location) = post_form(
        app,
        "/new",
        &bee,
        "owner=crew&name=shared&default_branch=main",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/crew/shared", "{location}");
    let (_, repo) = api(app, "GET", "/api/repos/crew/shared", "ada", None).await;
    assert_eq!(repo["owner"], "crew");

    // The organisation's page lists it and its people; bee governs it as
    // an owner would, and a member of nothing may not create under it.
    let (status, page) = page_with_cookie(app, "/crew", &bee).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#"href="/crew/shared""#) && page.contains("bee"),
        "{page}"
    );
    assert_eq!(
        get_with_cookie(app, "/crew/shared/settings", &bee).await,
        StatusCode::OK
    );
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "cat", "kind": "human", "display": "Cat" })),
    )
    .await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "cat",
        Some(json!({ "name": "mine", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "cat",
        Some(json!({ "name": "mine", "owner": "ada" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "not under another person either: {body}"
    );

    // An offer to an organisation is answered by a member, and the
    // repository takes the organisation's name.
    api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer",
        "ada",
        Some(json!({ "to": "crew" })),
    )
    .await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer/accept",
        "bee",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, repo) = api(app, "GET", "/api/repos/crew/demo", "bee", None).await;
    assert_eq!(repo["owner"], "crew");
    assert_eq!(repo["name"], "crew/demo");
}
