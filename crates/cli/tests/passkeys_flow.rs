//! Passkeys: the ceremonies are the browser's and the authenticator's;
//! what the forge owns is refusing to start without a public URL, parking
//! state that is spent once, refusing an answer it did not ask for, and
//! serving the script that drives it all under a content hash.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};

async fn post_json(
    app: &axum::Router,
    path: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_public_url_there_are_no_passkeys() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, body) = post_json(app, "/passkeys/login/begin", "", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (_, login) = page_with_cookie(app, "/login", "").await;
    assert!(!login.contains("Sign in with a passkey"));
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, settings) = page_with_cookie(app, "/you/settings", &cookie).await;
    assert!(!settings.contains("Add a passkey"));
}

#[tokio::test(flavor = "multi_thread")]
async fn ceremonies_start_park_state_once_and_refuse_answers_they_did_not_ask_for() {
    let forge = boot_with_passkeys().await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    // The pages offer it, and the script is served hashed and immutable.
    let (_, login) = page_with_cookie(app, "/login", "").await;
    assert!(login.contains(r#"data-passkey="login""#), "{login}");
    let (_, settings) = page_with_cookie(app, "/you/settings", &cookie).await;
    assert!(settings.contains(r#"data-passkey="register""#));
    let start = login.find("/assets/passkeys.").unwrap();
    let end = login[start..].find(".js").unwrap() + start + 3;
    let script = login[start..end].to_owned();
    let response = tower::ServiceExt::oneshot(
        app.clone(),
        Request::builder().uri(&script).body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );

    // Registration needs a signed-in person; sign-in does not.
    let (status, _) = post_json(app, "/passkeys/register/begin", "", json!({})).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a stranger is sent to sign in"
    );
    let (status, begin) = post_json(app, "/passkeys/register/begin", &cookie, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{begin}");
    assert!(
        begin["options"]["publicKey"]["challenge"].is_string(),
        "{begin}"
    );
    assert_eq!(begin["options"]["publicKey"]["rp"]["id"], "forge.example");
    let (status, login_begin) = post_json(app, "/passkeys/login/begin", "", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{login_begin}");
    assert!(login_begin["options"]["publicKey"]["challenge"].is_string());

    // An answer that is not a credential is refused, and the parked state
    // was spent by the attempt, so the same id cannot be tried again.
    let id = begin["id"].as_str().unwrap();
    let junk = json!({ "id": id, "credential": { "id": "x", "rawId": "eA", "type": "public-key",
        "response": { "attestationObject": "AA", "clientDataJSON": "AA" }, "extensions": {} } });
    let (status, body) = post_json(app, "/passkeys/register/finish", &cookie, junk.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = post_json(app, "/passkeys/register/finish", &cookie, junk).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("expired"),
        "{body}"
    );

    // Somebody else's parked state is not yours to finish.
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (_, begin) = post_json(app, "/passkeys/register/begin", &cookie, json!({})).await;
    let theirs = json!({ "id": begin["id"], "credential": { "id": "x", "rawId": "eA", "type": "public-key",
        "response": { "attestationObject": "AA", "clientDataJSON": "AA" }, "extensions": {} } });
    let (status, body) = post_json(app, "/passkeys/register/finish", &bee, theirs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("expired"),
        "{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_answer_is_judged_against_the_state_it_was_issued_for() {
    let forge = boot_with_passkeys().await;
    let app = &forge.app;
    let (_, begin) = post_json(app, "/passkeys/login/begin", "", json!({})).await;
    let id = begin["id"].as_str().unwrap();
    // A malformed answer to a live discoverable ceremony is refused as an
    // answer, not reported as an expired ceremony: the state was there.
    let junk = json!({ "id": id, "credential": { "id": "x", "rawId": "eA", "type": "public-key",
        "response": { "authenticatorData": "AA", "clientDataJSON": "AA", "signature": "AA", "userHandle": null },
        "extensions": {} } });
    let (status, body) = post_json(app, "/passkeys/login/finish", "", junk.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !body["error"].as_str().unwrap().contains("expired"),
        "{body}"
    );
    // And it was spent by that one attempt.
    let (_, body) = post_json(app, "/passkeys/login/finish", "", junk).await;
    assert!(
        body["error"].as_str().unwrap().contains("expired"),
        "{body}"
    );
}

#[test]
fn the_script_defines_what_it_uses() {
    let script = cairn_server::passkeys::SCRIPT;
    for helper in ["explain", "say", "post", "enc", "dec"] {
        let defined = script
            .find(&format!("var {helper} = "))
            .unwrap_or_else(|| panic!("{helper} defined"));
        let used = script.find(&format!("{helper}(")).unwrap();
        assert!(defined < used, "{helper} is used before it is defined");
    }
}
