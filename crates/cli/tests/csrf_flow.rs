//! A browser says where a request came from, and a write from somewhere
//! else is refused before any handler sees it.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;

async fn post_from(app: &axum::Router, cookie: &str, headers: &[(&str, &str)]) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri("/inbox/read")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", cookie)
        .header("host", "forge.example");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request.body(Body::from("all=1")).unwrap();
    tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap()
        .status()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_from_another_site_is_refused_and_one_from_here_is_not() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    // What a modern browser sends from a foreign page.
    assert_eq!(
        post_from(
            app,
            &cookie,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.example")
            ]
        )
        .await,
        StatusCode::FORBIDDEN
    );
    // An older browser: Origin alone.
    assert_eq!(
        post_from(app, &cookie, &[("origin", "https://evil.example")]).await,
        StatusCode::FORBIDDEN
    );
    // From here, both ways a browser says so.
    assert_eq!(
        post_from(
            app,
            &cookie,
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://forge.example")
            ]
        )
        .await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post_from(app, &cookie, &[("origin", "https://forge.example")]).await,
        StatusCode::SEE_OTHER
    );
    // A non-browser client says nothing about where it came from.
    assert_eq!(post_from(app, &cookie, &[]).await, StatusCode::SEE_OTHER);
}
