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
    // A browser under a strict referrer policy sends `Origin: null` on
    // its own forms; its `Sec-Fetch-Site` still vouches for the page.
    assert_eq!(
        post_from(
            app,
            &cookie,
            &[("sec-fetch-site", "same-origin"), ("origin", "null")]
        )
        .await,
        StatusCode::SEE_OTHER
    );
    // Without that word, null is nobody.
    assert_eq!(
        post_from(app, &cookie, &[("origin", "null")]).await,
        StatusCode::FORBIDDEN
    );
    // A sibling site is not this site.
    assert_eq!(
        post_from(
            app,
            &cookie,
            &[
                ("sec-fetch-site", "same-site"),
                ("origin", "https://other.forge.example")
            ]
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_referrer_policy_keeps_origin_meaningful_on_our_own_forms() {
    let forge = boot().await;
    let request = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(forge.app.clone(), request)
        .await
        .unwrap();
    // `no-referrer` would make browsers send `Origin: null` to us.
    assert_eq!(
        response.headers()["referrer-policy"].to_str().unwrap(),
        "same-origin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_page_keeps_the_viewers_theme_and_offers_a_way_home() {
    let forge = boot().await;
    let app = &forge.app;
    // An unknown path is a repository route, which asks a stranger to
    // sign in; the 404 is what a signed-in person sees.
    let (_, session) = sign_in_as(&forge, "ada").await;
    let request = Request::builder()
        .uri("/nowhere")
        .header("cookie", format!("cairn_theme=light; {session}"))
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        response.headers().get("x-cairn-fallback").is_none(),
        "the marker is ours, not the page's"
    );
    let body = String::from_utf8(
        http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains(r#"data-theme="light""#), "{body}");
    assert!(body.contains(r#"href="/""#), "a way home");
}
