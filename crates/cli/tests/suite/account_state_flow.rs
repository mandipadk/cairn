//! Account states: a deactivated principal cannot sign in, act, or be
//! acted for, from the same moment everywhere; reactivation undoes it.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn deactivation_shuts_every_door_at_once_and_reactivation_reopens_them() {
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
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (status, _) = page_with_cookie(app, "/you", &bee).await;
    assert_eq!(status, StatusCode::OK);
    let (status, minted) = api(
        app,
        "POST",
        "/api/principals/bee/tokens",
        "bee",
        Some(json!({ "label": "cli" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let bee_token = minted["secret"]
        .as_str()
        .or(minted["token"].as_str())
        .unwrap()
        .to_owned();

    // Only whoever runs the forge, and never on themselves.
    let (status, _) = api(
        app,
        "POST",
        "/api/principals/bee/state",
        "bee",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, refused) = api(
        app,
        "POST",
        "/api/principals/ada/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

    let (status, done) = api(
        app,
        "POST",
        "/api/principals/bee/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    // The browser session is over, the token is dead, the name cannot act.
    let (status, location) = get_redirect(app, "/you", &bee).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/login");
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &bee_token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, refused) = api(
        app,
        "POST",
        "/api/changes",
        "bee",
        Some(json!({ "repo": "demo", "target": "main", "title": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("deactivated"),
        "{refused}"
    );
    let (status, _) = sign_in(app, "bee", "a perfectly ordinary password").await;
    assert_ne!(status, StatusCode::SEE_OTHER, "sign-in must not succeed");
    // Twice is refused; the People page says so and offers the way back.
    let (status, _) = api(
        app,
        "POST",
        "/api/principals/bee/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, people) = page_with_cookie(app, "/people", &ada).await;
    assert!(people.contains("deactivated"), "{people}");
    assert!(people.contains("Reactivate"), "{people}");

    let (status, location) = post_form(app, "/people", &ada, "action=reactivate&id=bee").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert_eq!(location, "/people");
    let (status, _) = sign_in_as(&forge, "bee").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, log) = page_with_cookie(app, "/demo/log", &ada).await;
    let _ = log;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_agent_stops_at_its_next_request() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        "/api/principals/scout/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = api(
        app,
        "POST",
        "/api/principals/scout/state",
        "ada",
        Some(json!({ "active": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::OK);
}
