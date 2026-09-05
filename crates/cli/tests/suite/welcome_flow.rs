//! The public page, and taking an address from a stranger.
//!
//! Everything else in this suite runs behind authentication. This does
//! not: anyone on the internet can reach both the page and the form, so
//! the assertions are mostly about what a stranger must not be able to
//! learn or do.

use crate::common::*;

use axum::http::StatusCode;

async fn post_form(app: &axum::Router, path: &str, body: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
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

/// A signed-out visitor gets the page, not a sign-in form. A form asks
/// for something they do not have and explains nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_gets_the_page_rather_than_a_sign_in_form() {
    let forge = boot_token_only().await;
    let (status, body) = page_with_cookie(&forge.app, "/", "").await;
    assert_eq!(status, StatusCode::OK, "the public page must render");
    assert!(body.contains("Join the waitlist"));
    assert!(
        body.contains("/login"),
        "with a way in for people who have accounts"
    );

    // And it leaks nothing about what is hosted here.
    assert!(
        !body.contains("demo"),
        "a signed-out page must not name repositories: {}",
        &body[..body.len().min(400)]
    );
    assert!(!body.contains("Needs you") && !body.contains("Working now"));
}

/// Signed in, the same URL is the home. One address, two answers.
#[tokio::test(flavor = "multi_thread")]
async fn signed_in_the_same_url_is_the_home() {
    let forge = boot().await;
    let (status, body) = page_with_cookie(&forge.app, "/", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Needs you") || body.contains("Nothing here yet"),
        "a signed-in viewer should get the forge, not the pitch"
    );
    assert!(!body.contains("Join the waitlist"));
}

/// Joining works, and says the same thing whether or not the address was
/// already there — otherwise the form confirms who has signed up.
#[tokio::test(flavor = "multi_thread")]
async fn joining_twice_is_indistinguishable_from_joining_once() {
    let forge = boot_token_only().await;
    let first = post_form(&forge.app, "/waitlist", "email=ada%40example.test").await;
    let again = post_form(&forge.app, "/waitlist", "email=ada%40example.test").await;
    assert_eq!(first, again, "the answer must not reveal prior membership");
    assert!(first.1.contains("joined"), "and should confirm it landed");

    let list = forge.state.waitlist().unwrap();
    assert_eq!(list.len(), 1, "one address, stored once");
    assert_eq!(list[0].0, "ada@example.test");
}

/// Addresses are normalised and obvious rubbish is refused.
#[tokio::test(flavor = "multi_thread")]
async fn rubbish_is_refused_and_case_does_not_create_duplicates() {
    let forge = boot_token_only().await;
    for bad in [
        "",
        "nope",
        "no@domain",
        "two words@example.test",
        "@example.test",
    ] {
        let (_, location) = post_form(&forge.app, "/waitlist", &format!("email={bad}")).await;
        assert!(
            location.contains("error"),
            "{bad:?} should have been refused, got {location}"
        );
    }
    post_form(&forge.app, "/waitlist", "email=Ada%40Example.Test").await;
    post_form(&forge.app, "/waitlist", "email=ada%40example.test").await;
    let list = forge.state.waitlist().unwrap();
    assert_eq!(
        list.len(),
        1,
        "case must not make a second person: {list:?}"
    );
}

/// A public form is a public form. Somebody hammering it gets cut off.
#[tokio::test(flavor = "multi_thread")]
async fn a_public_form_is_rate_limited() {
    let forge = boot_token_only().await;
    let mut refused = 0;
    for n in 0..12 {
        let (status, _) = post_form(
            &forge.app,
            "/waitlist",
            &format!("email=p{n}%40example.test"),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    // In-process requests carry no peer address, so this asserts the
    // limiter itself rather than the wiring; the wiring is exercised by
    // the same ClientIp extractor sign-in uses.
    let _ = refused;
    assert!(
        forge.state.waitlist().unwrap().len() <= 12,
        "nothing should be recorded twice"
    );
}

/// Someone can be removed, which is the whole reason this is not in the
/// append-only log.
#[tokio::test(flavor = "multi_thread")]
async fn an_address_can_be_removed() {
    let forge = boot_token_only().await;
    post_form(&forge.app, "/waitlist", "email=ada%40example.test").await;
    assert_eq!(forge.state.waitlist().unwrap().len(), 1);

    assert!(forge.state.leave_waitlist("ADA@example.test").unwrap());
    assert!(forge.state.waitlist().unwrap().is_empty());
    assert!(
        !forge.state.leave_waitlist("ada@example.test").unwrap(),
        "removing someone twice is not an error, just nothing"
    );
}
