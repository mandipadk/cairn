//! Signing in as a person.
//!
//! Until now the only way into the browser was to paste an API token,
//! which is a credential meant for scripts and agents: long, unmemorable,
//! and equally powerful everywhere. A person needs a name and a password,
//! and the interesting assertions are about what that must *not* do —
//! confirm which names exist, survive a password change, or hand agents a
//! second and weaker way in.

use crate::common::*;

use axum::http::StatusCode;
use serde_json::json;

const GOOD: &str = "correct horse battery staple";

async fn set_password(forge: &Forge, who: &str, password: &str) -> StatusCode {
    api_with_token(
        &forge.app,
        "POST",
        &format!("/api/principals/{who}/password"),
        &forge.ada_token,
        Some(json!({ "password": password })),
    )
    .await
    .0
}

/// Sign in, get a session, and reach a page with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_and_password_signs_someone_in() {
    let forge = boot_token_only().await;
    assert_eq!(set_password(&forge, "ada", GOOD).await, StatusCode::OK);

    let (status, cookie) = sign_in(&forge.app, "ada", GOOD).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "sign-in should redirect");
    let cookie = cookie.expect("a session cookie");
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite"),
        "the session cookie needs its protections: {cookie}"
    );

    let session = cookie.split(';').next().unwrap().to_owned();
    let (status, _) = page_with_cookie(&forge.app, "/demo", &session).await;
    assert_eq!(status, StatusCode::OK, "the session should reach a page");

    // The cookie must not be the password, the name, or anything derived
    // from them.
    // A random id will sometimes contain three letters that happen to
    // spell the name; what matters is that it does not begin with the
    // name or carry the password.
    let value = session
        .trim_start_matches("cairn_session=")
        .trim_start_matches('s');
    assert!(
        !value.trim_start_matches("cairn_").starts_with("ada") && !session.contains("horse"),
        "the session id must be opaque: {session}"
    );
}

/// A wrong password and an unknown name must be indistinguishable —
/// otherwise the form confirms who has an account here.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_and_an_unknown_name_look_the_same() {
    let forge = boot_token_only().await;
    set_password(&forge, "ada", GOOD).await;

    let (_, wrong) = sign_in(&forge.app, "ada", "not the password at all").await;
    let (_, unknown) = sign_in(&forge.app, "nobody-here", "not the password at all").await;
    assert!(
        wrong.is_none() && unknown.is_none(),
        "neither should sign in"
    );

    let wrong_msg = redirect_of(&forge.app, "ada", "not the password at all").await;
    let unknown_msg = redirect_of(&forge.app, "nobody-here", "not the password at all").await;
    assert_eq!(
        wrong_msg, unknown_msg,
        "the answers must be identical, or the form enumerates accounts"
    );
}

/// Changing a password ends the sessions it was protecting.
#[tokio::test(flavor = "multi_thread")]
async fn changing_a_password_ends_existing_sessions() {
    let forge = boot_token_only().await;
    set_password(&forge, "ada", GOOD).await;
    let (_, cookie) = sign_in(&forge.app, "ada", GOOD).await;
    let session = cookie.unwrap().split(';').next().unwrap().to_owned();
    assert_eq!(
        page_with_cookie(&forge.app, "/demo", &session).await.0,
        StatusCode::OK
    );

    assert_eq!(
        set_password(&forge, "ada", "an entirely different secret").await,
        StatusCode::OK
    );
    assert_eq!(
        page_with_cookie(&forge.app, "/demo", &session).await.0,
        StatusCode::SEE_OTHER,
        "a password change that leaves old sessions alive locks nobody out"
    );
}

/// Agents authenticate with tokens. Giving them a password would be a
/// second, weaker way in.
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_cannot_be_given_a_password() {
    let forge = boot_token_only().await;
    let (status, body) = api_with_token(
        &forge.app,
        "POST",
        "/api/principals/scout/password",
        &forge.ada_token,
        Some(json!({ "password": GOOD })),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("tokens"),
        "the refusal should say what agents use instead: {body}"
    );
}

/// Passwords too short to be worth having are refused, and an agent may
/// not set someone else's.
#[tokio::test(flavor = "multi_thread")]
async fn weak_and_unauthorised_password_changes_are_refused() {
    let forge = boot_token_only().await;

    let (status, body) = api_with_token(
        &forge.app,
        "POST",
        "/api/principals/ada/password",
        &forge.ada_token,
        Some(json!({ "password": "short" })),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a short password should be refused: {body}"
    );

    let (status, body) = api_with_token(
        &forge.app,
        "POST",
        "/api/principals/ada/password",
        &forge.scout_token,
        Some(json!({ "password": GOOD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent must not set a human's password: {body}"
    );
}
