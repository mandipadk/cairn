//! What owning an agent does and does not let you do.
//!
//! Making agents somebody's was what let a person have them at all. It
//! also widened three doors: acting for an organisation asks no
//! capability of you, holding an agent skips the admin check, and both
//! of those reach their answer without ever consulting a session
//! credential's scope. These are the tests for the narrow versions.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

/// An open session as scout, and a credential drawn from it.
async fn a_credential(forge: &Forge) -> String {
    let app = &forge.app;
    let (status, task) = api_with_token(
        app,
        "POST",
        "/api/tasks",
        &forge.ada_token,
        Some(json!({ "title": "Work", "spec": "In demo.", "repo": "ada/demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{task}");
    let task_id = task["id"].as_str().unwrap().to_owned();
    api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/claim"),
        &forge.scout_token,
        None,
    )
    .await;
    let (status, session) = api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{task_id}/sessions"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let session = session["id"].as_str().unwrap().to_owned();
    let (status, drawn) = api_with_token(
        app,
        "POST",
        &format!("/api/sessions/{session}/credential"),
        &forge.scout_token,
        Some(json!({ "minutes": 30 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    drawn["token"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_credential_cannot_make_itself_permanent() {
    let forge = boot().await;
    let app = &forge.app;
    let credential = a_credential(&forge).await;

    // The whole point of a session credential is that it ends. Minting a
    // standing token with it would be a fifteen-minute thing making an
    // unending one, for itself or for anybody it holds.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals/scout/tokens",
        &credential,
        Some(json!({ "label": "forever" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("session credential"),
        "the refusal says why: {body}"
    );

    // Nor register a principal with it, which is the other standing act.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals",
        &credential,
        Some(json!({ "id": "spawn", "kind": "agent", "display": "Spawn" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // And it is not an admin, whatever its holder is the rest of the time.
    let (status, _) =
        api_with_token(app, "GET", "/api/principals/ada/quota", &credential, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "somebody else's numbers");

    // The standing token it was drawn under still does all of this.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals/scout/tokens",
        &forge.scout_token,
        Some(json!({ "label": "ordinary" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn belonging_to_an_organisation_is_not_a_capability() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    post_form(app, "/teams", &ada, "action=create&id=crew&display=Crew").await;
    // scout holds task and push, and nothing else. Being on the team
    // must not add to that: acting for an organisation you are in asks
    // no capability of you, so the capability has to be asked elsewhere.
    post_form(app, "/teams", &ada, "action=add&team=crew&member=scout").await;

    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.scout_token,
        Some(json!({ "id": "crews-hand", "kind": "agent", "display": "Hand", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("admin"),
        "the refusal names what is missing: {body}"
    );

    // A person on the team may, because a person may make their own.
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    post_form(app, "/teams", &ada, "action=add&team=crew&member=bee").await;
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "crews-hand", "kind": "agent", "display": "Hand", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn retiring_an_agent_is_yours_and_bringing_it_back_is_not() {
    let forge = boot().await;
    let app = &forge.app;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "bees-hand", "kind": "agent", "display": "Hand" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Whoever runs the forge stops a misbehaving agent.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/bees-hand/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Its owner must not be able to undo that: an undo in the hands of
    // the party it was aimed at is no lever at all.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/bees-hand/state",
        "bee",
        Some(json!({ "active": true })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (_, agent) = api(app, "GET", "/api/principals/bees-hand", "ada", None).await;
    assert_eq!(agent["active"], false, "still stopped");

    // Retiring one of their own is still theirs to do, and so is the
    // reactivation once the forge agrees.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/bees-hand/state",
        "ada",
        Some(json!({ "active": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/bees-hand/state",
        "bee",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_that_cannot_hold_anything_confers_nothing() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    post_form(app, "/teams", &ada, "action=create&id=crew&display=Crew").await;
    post_form(app, "/teams", &ada, "action=add&team=crew&member=bee").await;
    api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "crews-hand", "kind": "agent", "display": "Hand", "owner": "crew" })),
    )
    .await;
    // Bee holds it while the organisation stands.
    let (status, _) = api(
        app,
        "POST",
        "/api/principals/crews-hand/tokens",
        "bee",
        Some(json!({ "label": "work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The organisation is stopped. What it held, nobody holds through it.
    api(
        app,
        "POST",
        "/api/principals/crew/state",
        "ada",
        Some(json!({ "active": false })),
    )
    .await;
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/crews-hand/tokens",
        "bee",
        Some(json!({ "label": "after" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_to_act_for_somebody_says_nothing_about_who_exists() {
    let forge = boot().await;
    let app = &forge.app;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    // Bee is nobody in particular. Asking about a principal that exists
    // and one that does not must look the same from there.
    let answers: Vec<Value> = {
        let mut seen = Vec::new();
        for who in ["ada", "nobody-at-all"] {
            let (status, body) = api(
                app,
                "POST",
                &format!("/api/principals/{who}/state"),
                "bee",
                Some(json!({ "active": false })),
            )
            .await;
            seen.push(json!({ "status": status.as_u16(), "kind": body["kind"] }));
        }
        seen
    };
    assert_eq!(answers[0], answers[1], "one of these exists: {answers:?}");
}
