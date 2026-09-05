//! The page someone lands on after signing in.
//!
//! A list of repositories is what every other forge opens with, and it
//! answers a question nobody arrives with. The question is what wants
//! me — which does not care which repository the work happens to be in.
//! So the assertions here are about ranking *across* repositories, and
//! about the reasons travelling with the item.

use crate::common::*;

use axum::http::StatusCode;
use serde_json::json;

/// Open a change in `repo` that will want a human, and return its number.
async fn change_wanting_attention(forge: &Forge, repo: &str, title: &str, key: &str) -> i64 {
    let app = &forge.app;
    let (status, change) = api(
        app,
        "POST",
        "/api/changes",
        "ada",
        Some(json!({
            "repo": repo, "target": "main", "title": title, "external_key": key
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let id = change["id"].as_str().unwrap().to_owned();
    api(
        app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        "ada",
        Some(json!({ "commit_oid": "b".repeat(40), "message": title })),
    )
    .await;
    // A claim resting on argument alone is one of the things attention
    // routing exists to surface.
    api(
        app,
        "POST",
        &format!("/api/changes/{id}/claims"),
        "scout",
        Some(json!({
            "kind": "reasoning",
            "passed": true,
            "summary": "argued, not executed",
            "unchecked": ["everything"]
        })),
    )
    .await;
    change["number"].as_i64().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_home_ranks_what_wants_a_person_across_every_repository() {
    let forge = boot().await;
    let app = &forge.app;

    api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "second" })),
    )
    .await;

    let first = change_wanting_attention(&forge, "demo", "Something in demo", "Ia").await;
    let second = change_wanting_attention(&forge, "second", "Something in second", "Ib").await;

    let (status, body) = page_with_cookie(app, "/", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK, "home should render, not redirect");

    // Work from both repositories is on one list, each labelled with
    // where it lives — otherwise "#1" means nothing.
    assert!(body.contains("Needs you"));
    assert!(
        body.contains(&format!("demo #{first}")),
        "demo's change should be listed with its repository"
    );
    assert!(
        body.contains(&format!("second #{second}")),
        "so should the other repository's"
    );

    // The reason travels with it. A ranked list without reasons is just
    // an ordering someone has to trust.
    assert!(
        body.contains("argument") || body.contains("reasoning") || body.contains("nobody re-ran"),
        "each item should carry why it is there: {}",
        &body[..body.len().min(600)]
    );

    // The chrome is on every page: repositories in the sidebar, search,
    // and a way to create something.
    assert!(
        body.contains("Repositories"),
        "the sidebar lists repositories"
    );
    assert!(body.contains("second"), "including every one of them");
    assert!(
        body.contains("/search") && body.contains("/new"),
        "search and create belong in the bar, not in a README somewhere"
    );
    assert!(
        body.contains("Your changes"),
        "and a way back to your own work"
    );
}

/// With nothing waiting, the page says so rather than showing an empty
/// heading and letting the reader wonder whether it is broken.
#[tokio::test(flavor = "multi_thread")]
async fn a_quiet_forge_says_so() {
    let forge = boot().await;
    let (status, body) = page_with_cookie(&forge.app, "/", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Nothing is waiting on a human"));
}
