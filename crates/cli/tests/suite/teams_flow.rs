//! Teams from the page: whoever runs the forge makes one, puts people on
//! it, and grants it authority that its members then carry.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn a_team_is_made_staffed_and_granted_from_the_page() {
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
    let (_, minted) = api_with_token(
        app,
        "POST",
        "/api/principals/bee/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    let bee_token = minted["token"].as_str().unwrap().to_owned();
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, bee) = sign_in_as(&forge, "bee").await;

    assert_eq!(
        get_with_cookie(app, "/teams", &bee).await,
        StatusCode::NOT_FOUND
    );
    let (status, location) =
        post_form(app, "/teams", &ada, "action=create&id=crew&display=Crew").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/teams", "{location}");
    let (_, location) = post_form(app, "/teams", &ada, "action=add&team=crew&member=bee").await;
    assert_eq!(location, "/teams");
    let (_, location) = post_form(
        app,
        "/teams",
        &ada,
        "action=grant&team=crew&repo=demo&push=1&task=1",
    )
    .await;
    assert_eq!(location, "/teams");

    let (_, page) = page_with_cookie(app, "/teams", &ada).await;
    assert!(page.contains("crew") && page.contains("bee"), "{page}");
    assert!(page.contains("on demo") && page.contains("push"), "{page}");
    assert!(
        !page.contains(r#"class="repohead""#),
        "a section page is not a repository"
    );

    // Bee now acts with the team's authority, over the API like anyone.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &bee_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Crew work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, members) =
        api_with_token(app, "GET", "/api/teams/crew/members", &bee_token, None).await;
    assert_eq!(members["members"], json!(["bee"]));

    // And not once removed.
    post_form(app, "/teams", &ada, "action=remove&team=crew&member=bee").await;
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &bee_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "More" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
