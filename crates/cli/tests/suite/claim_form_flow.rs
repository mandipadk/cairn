//! A claim can be written where the change is read. The page offers the
//! same contract the API does, and the same refusals.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

async fn open_change_with_revision(forge: &Forge) -> String {
    let (status, change) = api_with_token(
        &forge.app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Needs a claim" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let id = change["id"].as_str().unwrap().to_owned();
    let (status, body) = api_with_token(
        &forge.app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "0".repeat(40), "message": "work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_written_on_the_page_is_the_same_claim_the_api_knows() {
    let forge = boot().await;
    let app = &forge.app;
    let change = open_change_with_revision(&forge).await;
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    let (status, location) = post_form(
        app,
        "/demo/changes/1/claim",
        &cookie,
        "revision=1&kind=test&command=cargo+test+--workspace&passed=yes\
         &summary=28+binaries+green&unchecked=docs%2C+the+import+path",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/demo/changes/1", "back to the change, no error");

    let (_, claims) = api_with_token(
        app,
        "GET",
        &format!("/api/changes/{change}/claims"),
        &forge.ada_token,
        None,
    )
    .await;
    let claim = &claims[0];
    assert_eq!(claim["kind"], "test");
    assert_eq!(claim["command"], "cargo test --workspace");
    assert_eq!(claim["passed"], true);
    assert_eq!(claim["by"], "ada");
    assert_eq!(claim["unchecked"], json!(["docs", "the import path"]));

    let (_, page) = page_with_cookie(app, "/demo/changes/1", &cookie).await;
    assert!(
        page.contains("28 binaries green"),
        "the claim shows where it was written"
    );
    assert!(page.contains("cargo test --workspace"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_refuses_what_the_api_refuses() {
    let forge = boot().await;
    let app = &forge.app;
    open_change_with_revision(&forge).await;
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    // No summary: the form's `required` is not the last line of defence.
    let (status, location) = post_form(
        app,
        "/demo/changes/1/claim",
        &cookie,
        "revision=1&kind=test&passed=yes&summary=+&unchecked=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("error="), "{location}");

    // A revision that does not exist.
    let (_, location) = post_form(
        app,
        "/demo/changes/1/claim",
        &cookie,
        "revision=7&kind=lint&passed=no&summary=nope",
    )
    .await;
    assert!(location.contains("error="), "{location}");

    // Somebody with no authority here is told there is nothing here.
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (status, _) = post_form(
        app,
        "/demo/changes/1/claim",
        &bee,
        "revision=1&kind=manual&passed=yes&summary=looked",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
