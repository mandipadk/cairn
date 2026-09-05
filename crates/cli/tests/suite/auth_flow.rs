//! Where authority stops.
//!
//! Capability checks are easy to write and easy to get subtly wrong,
//! and the failures are silent: a grant that outlives its revocation, a
//! repo-scoped grant that reaches further than its scope, an agent that
//! can widen its own authority. None of those show up in a happy path,
//! so every test here asks what is *refused* rather than what works.
//!
//! These run against a forge with the dev identity header switched off,
//! because that header bypasses tokens entirely — asserting anything
//! about authentication while it is on would prove nothing.

use crate::common::*;

use axum::http::StatusCode;
use serde_json::json;

/// Revoking a token must take effect on the next request, not on the
/// next restart or the next cache expiry.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_token_stops_working_on_the_next_request() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the token should work to begin with"
    );

    let (_, tokens) = api_with_token(
        app,
        "GET",
        "/api/principals/scout/tokens",
        &forge.ada_token,
        None,
    )
    .await;
    let token_id = tokens[0]["id"].as_str().unwrap().to_owned();

    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/tokens/{token_id}/revoke"),
        &forge.ada_token,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, refused) =
        api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked token must stop working at once: {refused}"
    );

    // The browser session is the same credential in a cookie, so it dies
    // with it. A signed-in tab outliving a revocation would make
    // revocation a suggestion.
    let response =
        get_with_cookie(app, "/demo", &format!("cairn_token={}", forge.scout_token)).await;
    assert_eq!(
        response,
        StatusCode::SEE_OTHER,
        "a revoked token in a cookie must be sent back to sign-in"
    );
}

/// Same for a grant: the capability disappears mid-session.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_grant_stops_working_on_the_next_request() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &forge.scout_token,
        Some(json!({ "title": "Something", "spec": "work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "scout holds the task capability");

    let (_, grants) = api_with_token(
        app,
        "GET",
        "/api/grants?grantee=scout",
        &forge.ada_token,
        None,
    )
    .await;
    let grant_id = grants
        .as_array()
        .and_then(|list| list.first())
        .and_then(|g| g["id"].as_str())
        .expect("scout has a grant")
        .to_owned();
    let (status, _) = api_with_token(
        app,
        "POST",
        &format!("/api/grants/{grant_id}/revoke"),
        &forge.ada_token,
        Some(json!({ "reason": "no longer needed" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &forge.scout_token,
        Some(json!({ "title": "Another", "spec": "work" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("task"),
        "the refusal should name the missing capability: {refused}"
    );
}

/// An expiry in the past authorises nothing, and the refusal happens
/// even though the grant row is still there and un-revoked.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_grant_authorises_nothing() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    // arbiter starts with no grants at all.
    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/grants",
        &forge.ada_token,
        Some(json!({
            "grantee": "arbiter",
            "actions": ["task"],
            "until": "2020-01-01T00:00:00Z"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "issuing a past expiry is allowed");

    let (_, arbiter_token) = api_with_token(
        app,
        "POST",
        "/api/principals/arbiter/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    let arbiter_token = arbiter_token["token"].as_str().unwrap().to_owned();

    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &arbiter_token,
        Some(json!({ "title": "Too late", "spec": "work" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an expired grant must not authorise: {refused}"
    );
}

/// A grant scoped to one repository must not reach another, and must
/// not cover operations that belong to no repository at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_repo_scoped_grant_stays_in_its_repo() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/repos",
        &forge.ada_token,
        Some(json!({ "name": "elsewhere" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    api_with_token(
        app,
        "POST",
        "/api/grants",
        &forge.ada_token,
        Some(json!({ "grantee": "arbiter", "repo": "demo", "actions": ["task"] })),
    )
    .await;
    let (_, token) = api_with_token(
        app,
        "POST",
        "/api/principals/arbiter/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    let arbiter_token = token["token"].as_str().unwrap().to_owned();

    let (status, _) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &arbiter_token,
        Some(json!({ "repo": "demo", "title": "In scope", "spec": "work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the granted repo is allowed");

    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &arbiter_token,
        Some(json!({ "repo": "elsewhere", "title": "Out of scope", "spec": "work" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a demo-scoped grant must not reach elsewhere: {refused}"
    );

    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &arbiter_token,
        Some(json!({ "title": "No repo at all", "spec": "work" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a repo-scoped grant must not cover repo-less work: {refused}"
    );
}

/// The escalation that matters: an agent widening its own authority, or
/// minting credentials for someone else.
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_cannot_widen_its_own_authority() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/grants",
        &forge.scout_token,
        Some(json!({ "grantee": "scout", "actions": ["admin", "merge"] })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("human"),
        "the refusal should say delegation is a human act: {refused}"
    );

    // Nor may it mint a credential for a human and act as them.
    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/principals/ada/tokens",
        &forge.scout_token,
        Some(json!({ "label": "borrowed" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent must not mint a token for a human: {refused}"
    );

    // Nor register a fresh principal to grant itself through.
    let (status, refused) = api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.scout_token,
        Some(json!({ "id": "puppet", "kind": "human", "display": "Puppet" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent must not register principals: {refused}"
    );
}

/// With dev identity off, the asserted-identity header is just a header.
#[tokio::test(flavor = "multi_thread")]
async fn the_dev_header_is_inert_when_dev_mode_is_off() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    let (status, refused) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "x-cairn-principal must carry no authority here: {refused}"
    );

    // And it cannot ride along with a real token to change who is acting.
    let (status, _) = api_with_token(app, "GET", "/api/repos/demo", &forge.scout_token, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// Vouching for your own work is not verification. The rule exists in
/// the core; nothing exercised it until now.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_cannot_be_verified_by_whoever_made_it() {
    let forge = boot_token_only().await;
    let app = &forge.app;

    // scout can both push and verify, so the only thing standing between
    // it and self-certification is the independence rule itself.
    api_with_token(
        app,
        "POST",
        "/api/grants",
        &forge.ada_token,
        Some(json!({ "grantee": "scout", "repo": "demo", "actions": ["verify"] })),
    )
    .await;

    let (status, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let change_id = change["id"].as_str().unwrap().to_owned();

    // A claim attaches to a revision, so the change needs one.
    let (status, revision) = api_with_token(
        app,
        "POST",
        &format!("/api/changes/{change_id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": "a".repeat(40), "message": "Work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revision}");

    let (status, claim) = api_with_token(
        app,
        "POST",
        &format!("/api/changes/{change_id}/claims"),
        &forge.scout_token,
        Some(json!({
            "kind": "test",
            "command": "cargo test",
            "passed": true,
            "summary": "all green"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claim}");
    let claim_id = claim["id"].as_str().unwrap().to_owned();

    let (status, refused) = api_with_token(
        app,
        "POST",
        &format!("/api/claims/{claim_id}/verify"),
        &forge.scout_token,
        Some(json!({ "agrees": true, "command": "cargo test", "observed": "exit 0" })),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the claim's author must not be able to verify it: {refused}"
    );
    assert!(
        refused["error"].as_str().unwrap().contains("independent"),
        "the refusal should say why: {refused}"
    );

    // Someone else holding the same capability may.
    api_with_token(
        app,
        "POST",
        "/api/grants",
        &forge.ada_token,
        Some(json!({ "grantee": "arbiter", "repo": "demo", "actions": ["verify"] })),
    )
    .await;
    let (_, token) = api_with_token(
        app,
        "POST",
        "/api/principals/arbiter/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    let (status, body) = api_with_token(
        app,
        "POST",
        &format!("/api/claims/{claim_id}/verify"),
        token["token"].as_str().unwrap(),
        Some(json!({ "agrees": true, "command": "cargo test", "observed": "exit 0" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an independent runner with the capability may verify: {body}"
    );
}
