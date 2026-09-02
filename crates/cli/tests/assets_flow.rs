//! The stylesheet is addressed by its content, so a deploy that changes
//! it changes the URL and nothing in between can serve a stale one.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use http_body_util::BodyExt;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, String, String) {
    let response = tower::ServiceExt::oneshot(
        app.clone(),
        Request::builder().uri(path).body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, cache, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_links_a_hashed_stylesheet_that_may_be_cached_forever() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, _, html) = get(app, "/login").await;
    assert_eq!(status, StatusCode::OK);
    let start = html.find("/assets/app.").expect("a stylesheet link");
    let end = html[start..].find(".css").unwrap() + start + 4;
    let href = &html[start..end];
    assert_ne!(href, "/assets/app.css", "the link carries a hash");

    let (status, cache, css) = get(app, href).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache, "public, max-age=31536000, immutable");
    assert!(css.contains("max-width: 760px"), "the real stylesheet");

    // The bare name still answers, but must be revalidated every time.
    let (status, cache, _) = get(app, "/assets/app.css").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache, "no-cache");

    // A hash that is not this binary's is not this binary's stylesheet.
    let (status, _, _) = get(app, "/assets/app.000000000000.css").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
