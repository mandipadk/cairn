//! The search page: filters that rewrite the query, a number that opens
//! a change, and a person who leads to their work.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn the_page_and_the_api_answer_the_same_question() {
    let forge = boot().await;
    let app = &forge.app;
    for title in ["Carry children onto the tip", "Also carry the children"] {
        let (status, body) = api_with_token(
            app,
            "POST",
            "/api/changes",
            &forge.scout_token,
            Some(json!({ "repo": "demo", "target": "main", "title": title })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    let (status, page) = page_with_cookie(app, "/search?q=carry+children", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let first = page.find("Carry children onto the tip").unwrap();
    let second = page.find("Also carry the children").unwrap();
    assert!(first < second, "the phrase-leading title ranks first");
    assert!(
        page.contains(r#"href="/search?q=carry%20children%20kind%3Achange""#)
            || page.contains("kind%3Achange"),
        "{page}"
    );

    // A number opens one change; a person leads to their work.
    let (_, page) = page_with_cookie(app, "/search?q=%232", &cookie).await;
    assert!(page.contains(r#"href="/demo/changes/2""#), "{page}");
    assert!(!page.contains(r#"href="/demo/changes/1""#));
    let (_, page) = page_with_cookie(app, "/search?q=scout+kind:person", &cookie).await;
    assert!(page.contains(r#"href="/search?q=by:scout""#), "{page}");
    let (_, page) = page_with_cookie(app, "/search?q=by:scout+kind:change", &cookie).await;
    assert!(page.contains("/demo/changes/1") && page.contains("/demo/changes/2"));

    // The API sees the same ranking, with its reasons.
    let (status, body) = api_with_token(
        app,
        "GET",
        "/api/search?q=carry+children",
        &forge.ada_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hits = body["hits"].as_array().unwrap();
    assert_eq!(hits[0]["title"], "Carry children onto the tip");
    assert_eq!(hits[0]["why"], "starts with it");
    assert!(hits[0]["score"].as_i64() > hits[1]["score"].as_i64());
}
