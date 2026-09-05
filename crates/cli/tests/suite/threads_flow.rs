//! Discussion as evidence: threads are anchored to things, a concern
//! holds the change until it is resolved, and every resolution says how.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

async fn change_with_revision(forge: &Forge) -> String {
    let (status, change) = api_with_token(
        &forge.app,
        "POST",
        "/api/changes",
        &forge.scout_token,
        Some(json!({ "repo": "demo", "target": "main", "title": "Under discussion" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    let id = change["id"].as_str().unwrap().to_owned();
    push(forge, &id, "first").await;
    id
}

async fn push(forge: &Forge, id: &str, message: &str) {
    let oid = format!("{:0>40}", message.len());
    let (status, body) = api_with_token(
        &forge.app,
        "POST",
        &format!("/api/changes/{id}/revisions"),
        &forge.scout_token,
        Some(json!({ "commit_oid": oid, "message": message })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_concern_holds_the_change_until_a_later_revision_resolves_it() {
    let forge = boot().await;
    let app = &forge.app;
    let id = change_with_revision(&forge).await;

    // ada raises a concern on a line of revision 1.
    let (status, opened) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({
            "anchor": { "on": "line", "path": "src/lib.rs", "side": "new", "line": 12 },
            "kind": "concern",
            "body": "This unwrap can panic on an empty repo."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let thread = opened["id"].as_str().unwrap().to_owned();
    assert_eq!(opened["event"]["kind"], "thread_opened");
    assert_eq!(opened["event"]["revision"], 1);

    // The concern is a fact the policy sees, by id.
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/readiness"),
        "ada",
        None,
    )
    .await;
    let unmet: Vec<&str> = readiness["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["satisfied"] == false)
        .map(|r| r["description"].as_str().unwrap())
        .collect();
    assert!(unmet.iter().any(|d| d.contains("concern")), "{readiness}");
    let concern = readiness["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains("concern"))
        .unwrap();
    assert!(
        concern["evidence"].as_str().unwrap().contains(&thread),
        "{concern}"
    );

    // The author answers in the thread; the concern still stands.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/reply"),
        "scout",
        Some(json!({ "body": "Good catch; fixing." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // "Fixed" has to name a revision after the one the concern was raised on.
    let (status, refused) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "scout",
        Some(json!({ "how": "fixed", "revision": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, refused) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "scout",
        Some(json!({ "how": "fixed" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

    push(&forge, &id, "second: guard the unwrap").await;
    let (status, resolved) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "scout",
        Some(json!({ "how": "fixed", "revision": 2, "note": "Returns an empty tree now." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");

    // The thread carries the whole story, and the change is free again.
    let (_, thread_json) = api(app, "GET", &format!("/api/threads/{thread}"), "ada", None).await;
    assert_eq!(thread_json["revision"], 1);
    assert_eq!(thread_json["anchor"]["on"], "line");
    assert_eq!(thread_json["anchor"]["line"], 12);
    assert_eq!(thread_json["replies"].as_array().unwrap().len(), 1);
    assert_eq!(thread_json["resolved"]["how"], "fixed");
    assert_eq!(thread_json["resolved"]["revision"], 2);
    assert_eq!(thread_json["resolved"]["by"], "scout");
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/readiness"),
        "ada",
        None,
    )
    .await;
    let concern = readiness["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains("concern"))
        .unwrap();
    assert_eq!(concern["satisfied"], true, "{concern}");

    // Resolved once; a second resolution is refused, not overwritten.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "ada",
        Some(json!({ "how": "answered" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Only what still stands, when asked.
    let (_, open) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/threads?state=open"),
        "ada",
        None,
    )
    .await;
    assert_eq!(open.as_array().unwrap().len(), 0);
    let (_, all) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/threads"),
        "ada",
        None,
    )
    .await;
    assert_eq!(all.as_array().unwrap().len(), 1);

    // ada, who raised it, hears what became of it.
    let (_, cookie) = sign_in_as(&forge, "ada").await;
    let (_, inbox) = page_with_cookie(app, "/inbox", &cookie).await;
    assert!(
        inbox.contains("scout replied to a concern on #1"),
        "{inbox}"
    );
    assert!(
        inbox.contains("scout resolved your concern on #1 as fixed"),
        "{inbox}"
    );
    // And the log says it in words.
    let (_, log) = page_with_cookie(app, "/demo/log", &cookie).await;
    assert!(log.contains("raised a concern on"), "{log}");
    assert!(log.contains("src/lib.rs:12"), "{log}");
    assert!(log.contains("as fixed in revision 2"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_is_the_openers_and_nobody_overrules_themselves() {
    let forge = boot().await;
    let app = &forge.app;
    let id = change_with_revision(&forge).await;
    let (_, opened) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({ "anchor": { "on": "change" }, "kind": "question", "body": "Why this approach?" })),
    )
    .await;
    let thread = opened["id"].as_str().unwrap().to_owned();

    // The author cannot make ada's question go away.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "scout",
        Some(json!({ "how": "withdrawn" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // ada cannot overrule herself.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "ada",
        Some(json!({ "how": "overruled" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The change's owner may overrule, on the record.
    let (status, resolved) = api(
        app,
        "POST",
        &format!("/api/threads/{thread}/resolve"),
        "scout",
        Some(json!({ "how": "overruled", "note": "Discussed on the task; keeping it." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_eq!(resolved["event"]["how"], "overruled");

    // A question never held the change: only concerns do.
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/readiness"),
        "ada",
        None,
    )
    .await;
    let concern = readiness["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains("concern"))
        .unwrap();
    assert_eq!(concern["satisfied"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn threads_are_anchored_to_real_things_and_need_a_part_in_the_repo() {
    let forge = boot().await;
    let app = &forge.app;
    let id = change_with_revision(&forge).await;

    // A claim anchor pins the claim's revision; a claim from elsewhere is not here.
    let (_, claim) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/claims"),
        "scout",
        Some(json!({ "kind": "test", "command": "cargo test", "passed": true, "summary": "ok" })),
    )
    .await;
    let claim_id = claim["id"].as_str().unwrap().to_owned();
    push(&forge, &id, "second").await;
    let (status, opened) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({ "anchor": { "on": "claim", "claim": claim_id }, "kind": "question", "body": "Which features were on?" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert_eq!(
        opened["event"]["revision"], 1,
        "pinned to the claim's revision, not the latest"
    );
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({ "anchor": { "on": "claim", "claim": "cl-nothing" }, "kind": "note", "body": "?" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A line is counted from 1, on a revision that exists.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({ "anchor": { "on": "line", "path": "a.rs", "side": "new", "line": 0 }, "kind": "note", "body": "?" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "ada",
        Some(json!({ "revision": 9, "anchor": { "on": "change" }, "kind": "note", "body": "?" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Somebody with no part in the repository may read, not discuss.
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{id}/threads"),
        "bee",
        Some(json!({ "anchor": { "on": "change" }, "kind": "concern", "body": "I object." })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
