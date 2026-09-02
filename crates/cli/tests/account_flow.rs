//! Doing account things without a terminal.
//!
//! Registering an agent, giving it a capability, minting and revoking a
//! token, changing a password: every one of these existed only as an API
//! call, which meant nobody but whoever ran the server could onboard.
//! The assertions that matter are about the awkward parts — a secret
//! that exists once, a grant that must stay narrow, and a password
//! change that has to end the session doing the changing.

mod common;
use common::*;

use axum::http::StatusCode;

async fn post(app: &axum::Router, path: &str, cookie: &str, body: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", cookie)
        .body(axum::body::Body::from(body.to_owned()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, location)
}

/// A token's secret exists exactly once, and the page says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_minted_token_is_shown_once_and_then_never_again() {
    let forge = boot().await;
    let app = &forge.app;

    let (_, location) = post(
        app,
        "/you/tokens",
        "cairn_dev=ada",
        "action=mint&label=laptop",
    )
    .await;
    assert!(
        location.contains("secret="),
        "the secret has to come back somehow: {location}"
    );

    let (status, body) = page_with_cookie(app, &location, "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Copy this now"), "and be unmissable");
    assert!(body.contains("cairn_"), "and actually be there");

    // Coming back later shows the token but not the secret.
    let (_, later) = page_with_cookie(app, "/you/tokens", "cairn_dev=ada").await;
    assert!(later.contains("laptop"), "the token is listed");
    assert!(
        !later.contains("Copy this now"),
        "but the secret is gone for good"
    );
}

/// Revoking from the page really revokes.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_can_be_revoked_from_the_page() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let cookie = {
        let (_, c) = sign_in_as(&forge, "ada").await;
        c
    };

    let (_, location) = post(app, "/you/tokens", &cookie, "action=mint&label=doomed").await;
    let secret = location
        .split("secret=")
        .nth(1)
        .expect("a secret")
        .to_owned();
    let secret = percent_decode(&secret);
    assert_eq!(
        api_with_token(app, "GET", "/api/repos/demo", &secret, None)
            .await
            .0,
        StatusCode::OK,
        "the fresh token works"
    );

    let (_, tokens) = api_with_token(
        app,
        "GET",
        "/api/principals/ada/tokens",
        &forge.ada_token,
        None,
    )
    .await;
    let id = tokens
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["label"] == "doomed")
        .expect("the token")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    post(
        app,
        "/you/tokens",
        &cookie,
        &format!("action=revoke&token={id}"),
    )
    .await;

    assert_eq!(
        api_with_token(app, "GET", "/api/repos/demo", &secret, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "and stops working the moment it is revoked"
    );
}

/// An agent arrives with a credential and no authority at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_agent_gets_a_token_but_no_capability() {
    let forge = boot().await;
    let app = &forge.app;

    let (_, location) = post(
        app,
        "/agents",
        "cairn_dev=ada",
        "action=register&id=helper&display=Helper&model=some-model",
    )
    .await;
    assert!(
        location.contains("secret="),
        "an agent needs a token to exist usefully"
    );
    let secret = percent_decode(location.split("secret=").nth(1).unwrap());

    // It can authenticate - its own record is the one thing a credential
    // with no authority may read - and do nothing else.
    assert_eq!(
        api_with_token(app, "GET", "/api/principals/helper", &secret, None)
            .await
            .0,
        StatusCode::OK,
        "the agent can identify itself"
    );
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &secret,
        Some(serde_json::json!({ "title": "x", "spec": "y" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "but holds no capability until somebody grants one: {body}"
    );

    // Grant it exactly one thing, scoped to one repository.
    post(
        app,
        "/agents",
        "cairn_dev=ada",
        "action=grant&grantee=helper&task=on&repo=demo",
    )
    .await;
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &secret,
        Some(serde_json::json!({ "repo": "demo", "title": "x", "spec": "y" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "now it can do that one thing");

    let (_, page) = page_with_cookie(app, "/agents", "cairn_dev=ada").await;
    assert!(page.contains("helper"), "and the page shows the agent");
    assert!(page.contains("task"), "with what it may do");
    assert!(page.contains("demo"), "and where");
}

/// Changing a password ends the session that changed it.
#[tokio::test(flavor = "multi_thread")]
async fn changing_your_password_signs_you_out() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    assert_eq!(
        page_with_cookie(app, "/you/settings", &cookie).await.0,
        StatusCode::OK
    );

    let (_, location) = post(
        app,
        "/you/settings",
        &cookie,
        "password=a+brand+new+secret+here&confirm=a+brand+new+secret+here",
    )
    .await;
    assert!(
        location.starts_with("/login"),
        "back to sign-in: {location}"
    );
    assert_eq!(
        page_with_cookie(app, "/you/settings", &cookie).await.0,
        StatusCode::SEE_OTHER,
        "the old session must be dead"
    );
}

/// Mistyping the confirmation changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_mistyped_confirmation_changes_nothing() {
    let forge = boot_token_only().await;
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, location) = post(
        &forge.app,
        "/you/settings",
        &cookie,
        "password=one+long+password+here&confirm=a+different+one+entirely",
    )
    .await;
    assert!(location.contains("error"), "{location}");
    assert_eq!(
        page_with_cookie(&forge.app, "/you/settings", &cookie)
            .await
            .0,
        StatusCode::OK,
        "and the session survives"
    );
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("20");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b' '));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
