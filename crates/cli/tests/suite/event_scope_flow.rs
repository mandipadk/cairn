//! Who an event is for.
//!
//! Visibility settled who may read a repository. The event feed was
//! never told: it authenticates the caller and then hands over every
//! event in the forge, so anyone with an account could read the titles,
//! claims, verdicts and merges of work they cannot clone — and the
//! account events of people they have never met.
//!
//! An event has a scope, and the scope is a property of the event rather
//! than something a page decides. That is the whole fix: the repository
//! log, an account's own activity, and an operator's view become three
//! filters over one log instead of three hand-written queries that drift.

use crate::common::*;

use axum::http::StatusCode;
use serde_json::json;

/// A second person with an account and no authority anywhere.
async fn outsider(forge: &Forge) -> String {
    api_with_token(
        &forge.app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (_, minted) = api_with_token(
        &forge.app,
        "POST",
        "/api/principals/bee/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    minted["token"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_feed_does_not_hand_private_work_to_strangers() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = outsider(&forge).await;

    // Ada does something in her own private repository.
    let (status, change) = api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.ada_token,
        Some(json!({
            "repo": "demo", "target": "main", "title": "CANARY secret plans"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");

    // Bee is signed in, and entitled to none of it.
    let (status, events) =
        api_with_token(app, "GET", "/api/events?after=0&limit=500", &bee, None).await;
    assert_eq!(status, StatusCode::OK);
    let text = events.to_string();
    assert!(
        !text.contains("CANARY"),
        "a stranger must not read the work of a repository they cannot clone"
    );
    assert!(
        !text.contains("password_set"),
        "nor anybody else's account events"
    );

    // Ada still sees her own.
    let (_, mine) = api_with_token(
        app,
        "GET",
        "/api/events?after=0&limit=500",
        &forge.ada_token,
        None,
    )
    .await;
    assert!(
        mine.to_string().contains("CANARY"),
        "the owner still sees their own work"
    );
}

/// Once bee is let in, the same feed shows the same work.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_opens_the_feed_exactly_as_far_as_the_repository() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = outsider(&forge).await;

    api_with_token(
        app,
        "POST",
        "/api/changes",
        &forge.ada_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "CANARY shared work" })),
    )
    .await;

    let seen = |token: String| {
        let app = app.clone();
        async move {
            let (_, events) =
                api_with_token(&app, "GET", "/api/events?after=0&limit=500", &token, None).await;
            events.to_string().contains("CANARY")
        }
    };
    assert!(!seen(bee.clone()).await, "not before the grant");

    api_with_token(
        app,
        "POST",
        "/api/grants",
        &forge.ada_token,
        Some(json!({ "grantee": "bee", "repo": "demo", "actions": ["review"] })),
    )
    .await;
    assert!(
        seen(bee).await,
        "and after it, exactly as far as the repository goes"
    );
}

/// Credentials are nobody else's business, including an admin's feed by
/// accident. The event exists; its subject is the only ordinary reader.
#[tokio::test(flavor = "multi_thread")]
async fn account_events_belong_to_their_subject() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let bee = outsider(&forge).await;

    api_with_token(
        app,
        "POST",
        "/api/principals/bee/password",
        &forge.ada_token,
        Some(json!({ "password": "a perfectly ordinary password" })),
    )
    .await;

    let (_, bees) = api_with_token(app, "GET", "/api/events?after=0&limit=500", &bee, None).await;
    let bees = bees.to_string();
    assert!(
        bees.contains("password_set"),
        "bee sees that their own password changed"
    );

    // A third person sees nothing of it.
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "cal", "kind": "human", "display": "Cal" })),
    )
    .await;
    let (_, minted) = api_with_token(
        app,
        "POST",
        "/api/principals/cal/tokens",
        &forge.ada_token,
        Some(json!({ "label": "test" })),
    )
    .await;
    let cal = minted["token"].as_str().unwrap();
    let (_, cals) = api_with_token(app, "GET", "/api/events?after=0&limit=500", cal, None).await;
    assert!(
        !cals.to_string().contains("password_set"),
        "and cal sees nobody's credential events but their own"
    );
}
